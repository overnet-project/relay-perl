use strict;
use warnings;

use AnyEvent;
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Socket::INET;
use IPC::Open3 qw(open3);
use JSON::PP qw(decode_json encode_json);
use MIME::Base64 qw(encode_base64);
use Net::Nostr::Client;
use Net::Nostr::Event;
use Net::Nostr::Group;
use Net::Nostr::Key;
use Overnet::Core::Nostr;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

our $CURRENT_IRC_LOG = '';
our $CURRENT_IRC_HEALTH = '';
our $CURRENT_IRC_STDERR;

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

sub _spawn_process {
  my (@command) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    @command,
  );
  close $stdin;
  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _stop_process {
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

sub _wait_for_health {
  my ($path) = @_;
  my $deadline = time() + 10;

  while (time() < $deadline) {
    if (-f $path && -s $path) {
      open my $fh, '<', $path
        or die "Can't open $path: $!";
      local $/;
      my $raw = <$fh>;
      close $fh;
      my $decoded = eval { decode_json($raw) };
      return $decoded if ref($decoded) eq 'HASH' && ($decoded->{status} || '') eq 'ready';
    }
    sleep 0.05;
  }

  die "Timed out waiting for ready health at $path\n";
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
  my (undef, $caller_file, $caller_line) = caller;

  while ($client->{read_buffer} !~ /\n/) {
    my $ready = IO::Select->new($client->{socket})->can_read($timeout_ms / 1000);
    unless ($ready) {
      my $extra = '';
      if (defined $CURRENT_IRC_LOG && length($CURRENT_IRC_LOG) && -f $CURRENT_IRC_LOG) {
        open my $fh, '<', $CURRENT_IRC_LOG
          or die "Can't open IRC log $CURRENT_IRC_LOG: $!";
        local $/;
        my $log = <$fh>;
        close $fh;
        $extra = "\nIRC log:\n$log";
      }
      if (defined $CURRENT_IRC_HEALTH && length($CURRENT_IRC_HEALTH) && -f $CURRENT_IRC_HEALTH) {
        open my $fh, '<', $CURRENT_IRC_HEALTH
          or die "Can't open IRC health $CURRENT_IRC_HEALTH: $!";
        local $/;
        my $health = <$fh>;
        close $fh;
        $extra .= "\nIRC health:\n$health";
      }
      if (defined $CURRENT_IRC_STDERR && IO::Select->new($CURRENT_IRC_STDERR)->can_read(0)) {
        my $stderr_text = '';
        while (sysread($CURRENT_IRC_STDERR, my $chunk, 4096)) {
          $stderr_text .= $chunk;
          last unless IO::Select->new($CURRENT_IRC_STDERR)->can_read(0);
        }
        $extra .= "\nIRC stderr:\n$stderr_text" if length $stderr_text;
      }
      die "Timed out waiting for IRC client line at $caller_file line $caller_line$extra\n";
    }

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected before sending a line at $caller_file line $caller_line\n"
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

sub _run_relay_backup {
  my (%args) = @_;
  my $stderr = gensym();
  my $pid = open3(
    undef,
    my $stdout,
    $stderr,
    $^X,
    $args{script},
    '--source-store-file', $args{source_store_file},
    '--backup-file', $args{backup_file},
  );

  my $stdout_text = do { local $/; <$stdout> };
  my $stderr_text = do { local $/; <$stderr> };
  close $stdout;
  close $stderr;
  waitpid($pid, 0);

  return {
    exit_code => $? >> 8,
    stdout    => $stdout_text,
    stderr    => $stderr_text,
  };
}

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $project_root = File::Spec->catdir($code_root, '..');
my $irc_root = File::Spec->catdir($project_root, 'overnet-program-irc');

my $relay_backup_script = File::Spec->catfile($code_root, 'bin', 'overnet-relay-backup.pl');
my $authority_relay_service_script = File::Spec->catfile($irc_root, 'bin', 'overnet-irc-authority-relay-service.pl');
my $irc_service_script = File::Spec->catfile($irc_root, 'bin', 'overnet-irc-service.pl');

ok -f $authority_relay_service_script, 'authoritative IRC relay service wrapper exists';

subtest 'backup-restored authoritative relay service plus fresh IRC service restores hosted channel state' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $relay_port = _free_port();
  my $irc_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $network = 'deploy-restore';
  my $server_name = 'irc.deploy.restore.test';
  my $channel = '#ops';
  my $group_id = 'ops';
  my $group_host = 'groups.deploy.restore.test';
  my $alice_key = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $seed_key = Net::Nostr::Key->new;
  my $relay_store = File::Spec->catfile($dir, 'authority-relay-store.json');
  my $relay_backup = File::Spec->catfile($dir, 'authority-relay-store.backup.json');
  my $relay_health = File::Spec->catfile($dir, 'authority-relay-health.json');
  my $relay_log = File::Spec->catfile($dir, 'authority-relay.log');
  my $restored_relay_health = File::Spec->catfile($dir, 'restored-authority-relay-health.json');
  my $restored_relay_log = File::Spec->catfile($dir, 'restored-authority-relay.log');
  my $irc_health = File::Spec->catfile($dir, 'irc-health.json');
  my $irc_log = File::Spec->catfile($dir, 'irc.log');
  my $signing_key_file = File::Spec->catfile($dir, 'irc-signing-key.pem');
  local $CURRENT_IRC_LOG = $irc_log;
  local $CURRENT_IRC_HEALTH = $irc_health;

  my $relay_proc = _spawn_process(
    $^X,
    $authority_relay_service_script,
    '--host', '127.0.0.1',
    '--port', $relay_port,
    '--relay-url', $relay_url,
    '--store-file', $relay_store,
    '--health-file', $relay_health,
    '--log-file', $relay_log,
  );

  eval {
    my $relay_ready = _wait_for_health($relay_health);
    is $relay_ready->{details}{relay_url}, $relay_url, 'authoritative relay health reports the relay URL';

    my $sign_group_event = sub {
      my ($event) = @_;
      return $seed_key->create_event(
        kind       => $event->{kind},
        created_at => $event->{created_at},
        content    => $event->{content},
        tags       => $event->{tags},
      )->to_hash;
    };

    my $metadata = Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_304_000,
      closed     => 1,
    )->to_hash;
    push @{$metadata->{tags}}, [ 'topic', 'Service Restored Topic' ];
    push @{$metadata->{tags}}, [ 'ban', '*!*@blocked.example' ];
    my $admins = Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_304_001,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash;
    my $members = Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_304_002,
      members    => [ $alice_pubkey ],
    )->to_hash;
    my $roles = Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_304_003,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash;
    my $joined = $seed_key->create_event(
      kind       => 9021,
      created_at => 1_744_304_004,
      content    => '',
      tags       => [
        [ 'h', $group_id ],
        [ 'overnet_actor', $alice_pubkey ],
        [ 'overnet_authority', 'e' x 64 ],
        [ 'overnet_sequence', 2 ],
      ],
    )->to_hash;

    for my $event ((map { $sign_group_event->($_) } ($metadata, $admins, $members, $roles)), $joined) {
      my $published = _publish_nostr_event_to_relay(
        relay_url => $relay_url,
        event     => $event,
      );
      ok $published->{accepted}, 'authoritative relay service accepts seeded authoritative state';
    }

    _stop_process($relay_proc);
    undef $relay_proc;

    my $backup = _run_relay_backup(
      script            => $relay_backup_script,
      source_store_file => $relay_store,
      backup_file       => $relay_backup,
    );
    is $backup->{exit_code}, 0, 'relay backup command succeeds for the service store';
    ok -f $relay_backup, 'relay backup command writes the backup file';

    $relay_proc = _spawn_process(
      $^X,
      $authority_relay_service_script,
      '--host', '127.0.0.1',
      '--port', $relay_port,
      '--relay-url', $relay_url,
      '--store-file', $relay_backup,
      '--health-file', $restored_relay_health,
      '--log-file', $restored_relay_log,
    );
    my $restored_ready = _wait_for_health($restored_relay_health);
    is $restored_ready->{details}{relay_url}, $relay_url, 'restored authoritative relay reports the same relay URL';

    my $restored_metadata_edit = $seed_key->create_event(
      kind       => 9002,
      created_at => 1_744_304_010,
      content    => '',
      tags       => [
        [ 'h', $group_id ],
        [ 'closed' ],
        [ 'topic', 'Service Restored Topic' ],
        [ 'ban', '*!*@blocked.example' ],
        [ 'overnet_actor', $alice_pubkey ],
        [ 'overnet_authority', 'e' x 64 ],
        [ 'overnet_sequence', 1 ],
      ],
    )->to_hash;
    my $restored_metadata_publish = _publish_nostr_event_to_relay(
      relay_url => $relay_url,
      event     => $restored_metadata_edit,
    );
    ok $restored_metadata_publish->{accepted},
      'restored authoritative relay accepts operator metadata edits';
    my $restored_events = Overnet::Core::Nostr->query_events(
      relay_url => $relay_url,
      filters   => [
        {
          kinds => [39000, 39001, 39002, 39003, 9002, 9021],
        },
      ],
      timeout_ms => 3_000,
    );
    my %restored_event_ids = map {
      defined($_->{id}) && !ref($_->{id}) ? ($_->{id} => 1) : ()
    } @{$restored_events || []};
    ok $restored_event_ids{$joined->{id}}, 'restored authoritative relay retains the durable join presence event';
    ok $restored_event_ids{$restored_metadata_edit->{id}}, 'restored authoritative relay retains the operator metadata edit';

    my $irc_proc = _spawn_process(
      $^X,
      $irc_service_script,
      '--adapter-id', 'irc.deploy.restore',
      '--network', $network,
      '--listen-host', '127.0.0.1',
      '--listen-port', $irc_port,
      '--server-name', $server_name,
      '--signing-key-file', $signing_key_file,
      '--group-host', $group_host,
      '--channel-group', "$channel=$group_id",
      '--authority-relay-url', $relay_url,
      '--authority-relay-poll-interval-ms', 50,
      '--authority-relay-query-timeout-ms', 3_000,
      '--health-file', $irc_health,
      '--log-file', $irc_log,
    );
    local $CURRENT_IRC_STDERR = $irc_proc->{stderr};

    my $irc_ready = _wait_for_health($irc_health);
    is $irc_ready->{details}{listen_port}, $irc_port, 'fresh IRC service wrapper reports the restored listen port';

    my $alice = _connect_irc_client($irc_port);
    _write_client_line($alice, 'NICK alice');
    _write_client_line($alice, 'USER alice 0 * :Alice Deploy Restore');
    _assert_registration_prelude(
      client      => $alice,
      nick        => 'alice',
      network     => $network,
      server_name => $server_name,
      timeout_ms  => 3_000,
    );

    _write_client_line($alice, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($alice, 3_000);
    like $challenge_line, qr/\A:\Q$server_name\E NOTICE alice :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      'fresh IRC service exposes an authoritative auth challenge after restore';
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;

    _write_client_line($alice, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $alice_key,
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $server_name,
        network     => $network,
      ),
    ));
    is _read_client_line($alice, 3_000),
      ":$server_name NOTICE alice :OVERNETAUTH AUTH $alice_pubkey",
      'fresh IRC service accepts the restored authoritative auth flow';

    _write_client_line($alice, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($alice, 3_000);
    like $delegate_line,
      qr/\A:\Q$server_name\E NOTICE alice :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      'fresh IRC service exposes relay-backed delegation parameters after restore';
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;

    _write_client_line($alice, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $alice_key,
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $server_name,
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => 'alice',
    ));
    is _read_client_line($alice, 3_000),
      ":$server_name NOTICE alice :OVERNETAUTH DELEGATE",
      'fresh IRC service acknowledges restored relay-backed delegation';

    close $alice->{socket};
    _stop_process($irc_proc);
  };
  my $error = $@;
  _stop_process($relay_proc);
  die $error if $error;
};

done_testing;
