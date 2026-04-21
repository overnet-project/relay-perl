use strict;
use warnings;

use AnyEvent;
use JSON::PP qw(encode_json);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Select;
use IO::Socket::INET;
use IPC::Open3 qw(open3);
use MIME::Base64 qw(encode_base64);
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

use Net::Nostr::Client;
use Net::Nostr::Event;
use Net::Nostr::Filter;
use Net::Nostr::Group;
use Net::Nostr::Key;
use Overnet::Program::Host;
use Overnet::Program::Runtime;
use Overnet::Relay::Sync;

my $program_path = File::Spec->catfile($FindBin::Bin, '..', '..', 'overnet-program-irc', 'bin', 'overnet-irc-server.pl');
my $irc_lib = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');
my $authoritative_relay_script = File::Spec->catfile($FindBin::Bin, 'authoritative-nip29-relay.pl');

sub _free_port {
  my $sock = IO::Socket::INET->new(
    Listen    => 1,
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Can't allocate free TCP port: $!";

  my $port = $sock->sockport;
  close $sock;
  return $port;
}

sub _spawn_authoritative_nip29_relay {
  my (%args) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    $^X,
    $authoritative_relay_script,
    '--host', '127.0.0.1',
    '--port', $args{port},
    '--relay-url', $args{relay_url},
    '--grant-kind', 14142,
    (defined $args{store_file} ? ('--store-file', $args{store_file}) : ()),
  );

  close $stdin;
  return {
    pid       => $pid,
    stdout    => $stdout,
    stderr    => $stderr,
    relay_url => $args{relay_url},
  };
}

sub _stop_authoritative_nip29_relay {
  my ($proc) = @_;
  return unless $proc && $proc->{pid};

  kill 'TERM', $proc->{pid};
  my $deadline = time() + 5;
  while (time() < $deadline) {
    my $reaped = waitpid($proc->{pid}, WNOHANG);
    last if $reaped == $proc->{pid};
    sleep 0.05;
  }

  if (waitpid($proc->{pid}, WNOHANG) == 0) {
    kill 'KILL', $proc->{pid};
    waitpid($proc->{pid}, 0);
  }

  close $proc->{stdout} if $proc->{stdout};
  close $proc->{stderr} if $proc->{stderr};
}

sub _wait_for_authoritative_nip29_relay_ready {
  my ($relay_url) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $ok = eval {
      my $client = Net::Nostr::Client->new;
      $client->connect($relay_url);
      $client->disconnect;
      1;
    };
    return 1 if $ok;
    sleep 0.05;
  }

  die "authoritative NIP-29 relay did not become ready at $relay_url\n";
}

sub _publish_nostr_event_to_relay {
  my (%args) = @_;
  my $client = Net::Nostr::Client->new;
  my $cv = AnyEvent->condvar;
  my $wire = Net::Nostr::Event->from_wire($args{event});
  my $event_id = $wire->id;

  $client->on(ok => sub {
    my ($current_id, $accepted, $message) = @_;
    return unless $current_id eq $event_id;
    $cv->send({
      accepted => $accepted ? 1 : 0,
      message  => $message,
    });
  });

  $client->connect($args{relay_url});
  $client->publish($wire);
  my $result = $cv->recv;
  $client->disconnect;
  return $result;
}

sub _sync_authoritative_events {
  my (%args) = @_;
  my $sync = Overnet::Relay::Sync->new(
    local_url => $args{local_url},
  );

  return $sync->sync_once(
    remote_url       => $args{remote_url},
    subscription_id  => $args{subscription_id},
    filter           => Net::Nostr::Filter->new(
      kinds => [39000, 39001, 39002, 39003, 9000, 9001, 9002, 9009, 9021, 9022],
    ),
  );
}

sub _wait_for_ready_details {
  my ($host) = @_;

  my $ready = $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      my ($current_host) = @_;
      for my $notification (@{$current_host->observed_notifications}) {
        next unless ($notification->{method} || '') eq 'program.health';
        next unless ($notification->{params}{status} || '') eq 'ready';
        next unless ref($notification->{params}{details}) eq 'HASH';
        return 1 if defined $notification->{params}{details}{listen_port};
      }
      return 0;
    },
  );
  return undef unless $ready;

  for my $notification (@{$host->observed_notifications}) {
    next unless ($notification->{method} || '') eq 'program.health';
    next unless ($notification->{params}{status} || '') eq 'ready';
    next unless ref($notification->{params}{details}) eq 'HASH';
    return $notification->{params}{details};
  }

  return undef;
}

sub _connect_irc_client {
  my ($port) = @_;

  my $socket = IO::Socket::INET->new(
    PeerHost => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => 1,
  ) or die "Can't connect fake IRC client to 127.0.0.1:$port: $!";

  binmode($socket, ':raw');
  $socket->autoflush(1);
  return {
    socket      => $socket,
    read_buffer => '',
  };
}

sub _read_client_line {
  my ($client, $timeout_ms) = @_;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    die "Timed out waiting for IRC client line\n"
      unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected before sending a line\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _read_client_line_optional {
  my ($client, $timeout_ms) = @_;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    return undef unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected unexpectedly\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _write_client_line {
  my ($client, $line) = @_;

  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    die "Failed to write fake IRC client line: $!\n"
      unless defined $written;
    $offset += $written;
  }
}

sub _assert_registration_prelude {
  my (%args) = @_;

  is_deeply [
    _read_client_line($args{client}, $args{timeout_ms}),
    _read_client_line($args{client}, $args{timeout_ms}),
    _read_client_line($args{client}, $args{timeout_ms}),
  ], [
    sprintf(':%s 001 %s :Welcome to Overnet IRC', $args{server_name}, $args{nick}),
    sprintf(':%s 005 %s CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=%s :are supported by this server', $args{server_name}, $args{nick}, $args{network}),
    sprintf(':%s 422 %s :MOTD File is missing', $args{server_name}, $args{nick}),
  ], "$args{nick} receives the minimal registration prelude";
}

sub _pump_hosts_until {
  my (%args) = @_;
  my $hosts = $args{hosts} || [];
  my $timeout_ms = $args{timeout_ms} || 1_000;
  my $pump_timeout_ms = $args{pump_timeout_ms} || 50;
  my $condition = $args{condition} || sub { 0 };
  my $deadline = time() + ($timeout_ms / 1000);

  while (time() < $deadline) {
    for my $host (@{$hosts}) {
      $host->pump(timeout_ms => $pump_timeout_ms);
    }
    return 1 if $condition->();
    sleep 0.05;
  }

  return 0;
}

sub _pump_hosts_until_client_lines {
  my (%args) = @_;
  my $client = $args{client} || return undef;
  my $count = $args{count} || 1;
  my @lines;

  my $ok = _pump_hosts_until(
    hosts           => $args{hosts} || [],
    timeout_ms      => $args{timeout_ms},
    pump_timeout_ms => $args{pump_timeout_ms},
    condition       => sub {
      while (@lines < $count) {
        my $line = _read_client_line_optional($client, 10);
        last unless defined $line;
        push @lines, $line;
      }
      return @lines >= $count;
    },
  );

  return undef unless $ok;
  return \@lines;
}

sub _authoritative_auth_scope {
  my (%args) = @_;
  return sprintf('irc://%s/%s', $args{server_name}, $args{network});
}

sub _build_authoritative_auth_payload {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => 22242,
    created_at => 1_744_301_000,
    content    => '',
    tags       => [
      [ 'relay', $args{scope} ],
      [ 'challenge', $args{challenge} ],
    ],
  );
  return encode_base64(encode_json($event->to_hash), '');
}

sub _build_authoritative_delegate_payload {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => 14142,
    created_at => 1_744_301_100,
    content    => '',
    tags       => [
      [ 'relay', $args{relay_url} ],
      [ 'server', $args{scope} ],
      [ 'delegate', $args{delegate_pubkey} ],
      [ 'session', $args{session_id} ],
      [ 'expires_at', $args{expires_at} ],
      (defined($args{nick}) ? ([ 'nick', $args{nick} ]) : ()),
    ],
  );
  return encode_base64(encode_json($event->to_hash), '');
}

sub _authenticate_and_delegate {
  my (%args) = @_;
  my $client = $args{client};
  my $host = $args{host};

  _write_client_line($client, 'OVERNETAUTH CHALLENGE');
  ok $host->pump(timeout_ms => $args{pump_timeout_ms}) >= 0,
    "$args{nick} pumps the auth challenge request";
  my $challenge_line = _read_client_line($client, 1_000);
  like $challenge_line,
    qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    "$args{nick} receives an authoritative auth challenge";
  $challenge_line =~ /([0-9a-f]{64})\z/;
  my $challenge = $1;

  _write_client_line($client, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $args{key},
    challenge => $challenge,
    scope     => _authoritative_auth_scope(
      server_name => $args{server_name},
      network     => $args{network},
    ),
  ));
  ok $host->pump(timeout_ms => $args{pump_timeout_ms}) >= 0,
    "$args{nick} pumps the auth response";
  is _read_client_line($client, 1_000),
    ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH " . $args{key}->pubkey_hex,
    "$args{nick} authenticates the authoritative pubkey";

  _write_client_line($client, 'OVERNETAUTH DELEGATE');
  ok $host->pump(timeout_ms => $args{pump_timeout_ms}) >= 0,
    "$args{nick} pumps the delegation parameter request";
  my $delegate_line = _read_client_line($client, 3_000);
  like $delegate_line,
    qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$args{relay_url}\E (\d+)\z/,
    "$args{nick} receives relay-backed delegation parameters";
  my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$args{relay_url}\E (\d+)\z/;

  _write_client_line($client, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
    key             => $args{key},
    relay_url       => $args{relay_url},
    scope           => _authoritative_auth_scope(
      server_name => $args{server_name},
      network     => $args{network},
    ),
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    nick            => $args{nick},
  ));

  my $delegate_ack = _pump_hosts_until_client_lines(
    hosts           => [$host],
    client          => $client,
    count           => 1,
    pump_timeout_ms => $args{pump_timeout_ms},
    timeout_ms      => $args{timeout_ms},
  );
  ok $delegate_ack, "$args{nick} receives the delegation acknowledgement";
  is $delegate_ack->[0],
    ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
    "$args{nick} establishes the relay-backed delegation";
}

subtest 'IRC server recovers authoritative state from a second live relay without widening or duplicating bootstrap' => sub {
  my $network = 'irc.authority.relay.failover.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $relay_host_pump_ms = 200;
  my $relay_propagation_timeout_ms = 5_000;
  my $relay_a_port = _free_port();
  my $relay_b_port = _free_port();
  my $relay_a_url = "ws://127.0.0.1:$relay_a_port";
  my $relay_b_url = "ws://127.0.0.1:$relay_b_port";
  my $server_name = 'overnet-failover.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $tmpdir = tempdir(CLEANUP => 1);
  my $relay_a_store_file = File::Spec->catfile($tmpdir, 'relay-a-store.json');
  my $relay_b_store_file = File::Spec->catfile($tmpdir, 'relay-b-store.json');

  my $relay_a = _spawn_authoritative_nip29_relay(
    port       => $relay_a_port,
    relay_url  => $relay_a_url,
    store_file => $relay_a_store_file,
  );
  my $relay_b = _spawn_authoritative_nip29_relay(
    port       => $relay_b_port,
    relay_url  => $relay_b_url,
    store_file => $relay_b_store_file,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_a_url);
  _wait_for_authoritative_nip29_relay_ready($relay_b_url);

  my $seed_key = Net::Nostr::Key->new;
  my $sign_group_event = sub {
    my ($event) = @_;
    return $seed_key->create_event(
      kind       => $event->{kind},
      created_at => $event->{created_at},
      content    => $event->{content},
      tags       => $event->{tags},
    )->to_hash;
  };

  my $metadata_before = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => $group_id,
    created_at => 1_744_303_000,
    closed     => 1,
  )->to_hash;
  push @{$metadata_before->{tags}}, [ 'topic', 'Relay A Topic' ];
  my $admins_before = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => $group_id,
    created_at => 1_744_303_001,
    members    => [
      {
        pubkey => $alice_pubkey,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;
  my $members_before = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => $group_id,
    created_at => 1_744_303_002,
    members    => [ $alice_pubkey ],
  )->to_hash;
  my $roles_before = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => $group_id,
    created_at => 1_744_303_003,
    roles      => [
      { name => 'irc.operator' },
      { name => 'irc.voice' },
    ],
  )->to_hash;

  my @seed_events = map { $sign_group_event->($_) } (
    $metadata_before,
    $admins_before,
    $members_before,
    $roles_before,
  );

  for my $event (@seed_events) {
    my $published = _publish_nostr_event_to_relay(
      relay_url => $relay_a_url,
      event     => $event,
    );
    ok $published->{accepted}, 'relay A accepts the initial authoritative seed event';
  }

  my $initial_sync = _sync_authoritative_events(
    remote_url      => $relay_a_url,
    local_url       => $relay_b_url,
    subscription_id => 'relay-a-to-b-seed',
  );
  is_deeply $initial_sync->{fetched_ids}, [ sort map { $_->{id} } @seed_events ],
    'relay B fetches the initial authoritative seed state through sync';
  is_deeply $initial_sync->{unresolved_ids}, [],
    'relay B resolves the full initial authoritative seed state through sync';

  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-relay-failover-key.pem');
  my $signing_key = Net::Nostr::Key->new;
  $signing_key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.relay.failover',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => $server_name,
      signing_key_file => $key_path,
      adapter_config   => {
        network           => $network,
        authority_profile => 'nip29',
        group_host        => $group_host,
        channel_groups    => {
          $channel => $group_id,
        },
      },
      authority_relay => {
        url              => $relay_a_url,
        poll_interval_ms => 50,
      },
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.relay.failover',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real authoritative IRC adapter for failover coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.append',
      'events.read',
      'nostr.read',
      'nostr.write',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'            => {},
      'adapters.map_input'               => {},
      'adapters.derive'                  => {},
      'adapters.close_session'           => {},
      'events.append'                    => {},
      'events.read'                      => {},
      'nostr.publish_event'              => {},
      'nostr.query_events'               => {},
      'nostr.open_subscription'          => {},
      'nostr.read_subscription_snapshot' => {},
      'nostr.close_subscription'         => {},
      'subscriptions.open'               => {},
      'subscriptions.close'              => {},
      'overnet.emit_event'               => {},
      'overnet.emit_state'               => {},
      'overnet.emit_private_message'     => {},
      'overnet.emit_capabilities'        => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'failover authoritative server reaches ready state';
  my $ready = _wait_for_ready_details($host);
  ok $ready, 'failover authoritative server publishes ready health details';

  my $alice = _connect_irc_client($ready->{listen_port});
  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Relay Failover');
  _assert_registration_prelude(
    client      => $alice,
    nick        => 'alice',
    network     => $network,
    server_name => $server_name,
    timeout_ms  => 3_000,
  );

  _authenticate_and_delegate(
    client          => $alice,
    host            => $host,
    key             => $alice_key,
    nick            => 'alice',
    network         => $network,
    relay_url       => $relay_a_url,
    server_name     => $server_name,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'failover authoritative server pumps the initial JOIN';
  my $join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host],
    client          => $alice,
    count           => 4,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $join_bootstrap, 'joined client receives the initial authoritative bootstrap';
  is_deeply $join_bootstrap, [
    ":alice JOIN $channel",
    ":$server_name TOPIC $channel :Relay A Topic",
    ":$server_name 353 alice = $channel :\@alice",
    ":$server_name 366 alice $channel :End of /NAMES list.",
  ], 'initial authoritative JOIN bootstrap uses relay A state';

  _stop_authoritative_nip29_relay($relay_a);

  my $metadata_after = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => $group_id,
    created_at => 1_744_303_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata_after->{tags}}, [ 'topic', 'Relay B Catch-Up Topic' ];
  push @{$metadata_after->{tags}}, [ 'ban', '*!*@*' ];
  $metadata_after = $sign_group_event->($metadata_after);

  my $published = _publish_nostr_event_to_relay(
    relay_url => $relay_b_url,
    event     => $metadata_after,
  );
  ok $published->{accepted}, 'relay B accepts the newer authoritative state while relay A is down';

  $relay_a = _spawn_authoritative_nip29_relay(
    port       => $relay_a_port,
    relay_url  => $relay_a_url,
    store_file => $relay_a_store_file,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_a_url);

  my $recovery_sync = _sync_authoritative_events(
    remote_url      => $relay_b_url,
    local_url       => $relay_a_url,
    subscription_id => 'relay-b-to-a-recovery',
  );
  ok grep({ $_ eq $metadata_after->{id} } @{$recovery_sync->{fetched_ids} || []}),
    'relay A fetches the newer authoritative state during recovery sync';
  is_deeply $recovery_sync->{unresolved_ids}, [],
    'relay A resolves the full recovery sync set';

  my @replay_lines;
  for (1 .. 8) {
    $host->pump(timeout_ms => $relay_host_pump_ms);
    while (defined(my $line = _read_client_line_optional($alice, 20))) {
      push @replay_lines, $line;
    }
    sleep 0.05;
  }
  ok !grep { $_ eq ":alice JOIN $channel" } @replay_lines,
    'relay catch-up does not replay the client JOIN bootstrap';

  _write_client_line($alice, "TOPIC $channel");
  ok _pump_hosts_until(
    hosts           => [$host],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($alice, 50);
      return defined($line) && $line eq ":$server_name 332 alice $channel :Relay B Catch-Up Topic" ? 1 : 0;
    },
  ), 'joined client sees the catch-up topic from relay B after relay A recovery';

  _write_client_line($alice, "MODE $channel +b");
  ok $host->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'failover authoritative server pumps the recovered ban-list query';
  my $ban_lines = _pump_hosts_until_client_lines(
    hosts           => [$host],
    client          => $alice,
    count           => 2,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $ban_lines, 'recovered authoritative state returns ban-list lines';
  is_deeply $ban_lines, [
    ":$server_name 367 alice $channel *!*\@* $server_name 0",
    ":$server_name 368 alice $channel :End of channel ban list",
  ], 'recovered authoritative state preserves restrictive metadata instead of widening';

  my $shutdown = $host->request_shutdown(reason => 'relay failover authoritative test complete');
  is $shutdown->{state}, 'shutdown_complete', 'failover authoritative server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'failover authoritative server exits cleanly';

  close $alice->{socket};
  _stop_authoritative_nip29_relay($relay_a);
  _stop_authoritative_nip29_relay($relay_b);
};

done_testing;
