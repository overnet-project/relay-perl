use strict;
use warnings;
use AnyEvent;
use Test::More;
use JSON::PP qw(decode_json encode_json);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);
use IPC::Open3 qw(open3);
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(sleep time);

use Net::Nostr::Client;
use Net::Nostr::DirectMessage;
use Net::Nostr::Event;
use Net::Nostr::Filter;
use Net::Nostr::Group;
use Net::Nostr::Key;
use Overnet::Core::Nostr;
use Overnet::Program::Host;
use Overnet::Program::Runtime;

my $program_path = File::Spec->catfile($FindBin::Bin, '..', '..', 'overnet-program-irc', 'bin', 'overnet-irc-server.pl');
my $irc_lib = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');
my $spec_irc_dir = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-spec', 'fixtures', 'irc');
my $authoritative_relay_script = File::Spec->catfile($FindBin::Bin, 'authoritative-nip29-relay.pl');
my $program_irc_server_group = $ENV{OVERNET_IRC_SERVER_GROUP} || 'base';

die "Unknown OVERNET_IRC_SERVER_GROUP: $program_irc_server_group\n"
  unless $program_irc_server_group eq 'base'
    || $program_irc_server_group eq 'relay'
    || $program_irc_server_group eq 'all';

sub _run_program_irc_server_group {
  my ($group) = @_;
  return 1 if $program_irc_server_group eq 'all';
  return $program_irc_server_group eq $group;
}

sub _load_irc_fixture {
  my ($name) = @_;
  my $path = File::Spec->catfile($spec_irc_dir, $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;
  return decode_json($json);
}

sub _method_count {
  my ($entries, $direction, $type, $method) = @_;
  my $count = 0;

  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq $type;
    next unless ($entry->{message}{method} || '') eq $method;
    $count++;
  }

  return $count;
}

sub _request_count_matching {
  my ($entries, $direction, $method, $predicate) = @_;
  my $count = 0;

  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq 'request';
    next unless ($entry->{message}{method} || '') eq $method;
    next if $predicate && !$predicate->($entry->{message}{params} || {});
    $count++;
  }

  return $count;
}

sub _last_request_matching {
  my ($entries, $direction, $method, $predicate) = @_;
  my $matched;

  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq 'request';
    next unless ($entry->{message}{method} || '') eq $method;
    my $params = $entry->{message}{params} || {};
    next if $predicate && !$predicate->($params);
    $matched = $params;
  }

  return $matched;
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

sub _wait_for_dm_subscription_count {
  my ($host, $count) = @_;

  return $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.open',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= $count;
    },
  );
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

sub _connect_irc_client_tls {
  my ($port) = @_;

  my $socket = IO::Socket::SSL->new(
    PeerHost        => '127.0.0.1',
    PeerPort        => $port,
    SSL_verify_mode => SSL_VERIFY_NONE,
    Timeout         => 1,
  ) or die "Can't connect fake TLS IRC client to 127.0.0.1:$port: " . IO::Socket::SSL::errstr();

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
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    die "Timed out waiting for IRC client line at $caller_file line $caller_line\n"
      unless @ready;

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

sub _read_client_lines {
  my ($client, $count, $timeout_ms) = @_;
  my @lines;

  for (1 .. $count) {
    push @lines, _read_client_line($client, $timeout_ms);
  }

  return @lines;
}

sub _assert_registration_prelude {
  my (%args) = @_;
  my $client = $args{client};
  my $nick = $args{nick};
  my $network = $args{network};
  my $server_name = $args{server_name} || 'overnet.irc.local';
  my $timeout_ms = $args{timeout_ms} || 1_000;

  is_deeply [
    _read_client_lines($client, 3, $timeout_ms),
  ], [
    sprintf(':%s 001 %s :Welcome to Overnet IRC', $server_name, $nick),
    sprintf(':%s 005 %s CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=%s :are supported by this server', $server_name, $nick, $network),
    sprintf(':%s 422 %s :MOTD File is missing', $server_name, $nick),
  ], "$nick receives the minimal registration prelude";
}

sub _read_client_line_optional {
  my ($client, $timeout_ms) = @_;
  my (undef, $caller_file, $caller_line) = caller;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    return undef unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected unexpectedly at $caller_file line $caller_line\n"
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

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _extract_trailing_text {
  my ($line) = @_;
  return undef unless defined $line && !ref($line);
  return undef unless $line =~ / :(.*)\z/;
  return $1;
}

sub _authoritative_nip29_stream_name {
  my (%args) = @_;
  return join ':',
    'irc.authority.nip29',
    $args{network},
    $args{group_host},
    $args{group_id};
}

sub _authoritative_auth_scope {
  my (%args) = @_;
  return sprintf('irc://%s/%s', $args{server_name}, $args{network});
}

sub _authoritative_grant_kind {
  return 14142;
}

sub _build_authoritative_auth_event_hash {
  my (%args) = @_;
  my $key = $args{key};
  my $challenge = $args{challenge};
  my $scope = $args{scope};
  my $created_at = exists $args{created_at} ? $args{created_at} : 1_744_301_000;

  my $event = $key->create_event(
    kind       => 22242,
    created_at => $created_at,
    content    => '',
    tags       => [
      [ 'relay', $scope ],
      [ 'challenge', $challenge ],
    ],
  );

  return $event->to_hash;
}

sub _build_authoritative_auth_payload {
  my (%args) = @_;
  return encode_base64(
    encode_json(
      _build_authoritative_auth_event_hash(%args)
    ),
    '',
  );
}

sub _build_authoritative_delegate_event_hash {
  my (%args) = @_;
  my $key = $args{key};
  my $relay_url = $args{relay_url};
  my $scope = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id = $args{session_id};
  my $expires_at = $args{expires_at};
  my $nick = $args{nick};
  my $created_at = exists $args{created_at} ? $args{created_at} : 1_744_301_100;

  my $event = $key->create_event(
    kind       => _authoritative_grant_kind(),
    created_at => $created_at,
    content    => '',
    tags       => [
      [ 'relay', $relay_url ],
      [ 'server', $scope ],
      [ 'delegate', $delegate_pubkey ],
      [ 'session', $session_id ],
      [ 'expires_at', $expires_at ],
      (defined $nick ? ([ 'nick', $nick ]) : ()),
    ],
  );

  return $event->to_hash;
}

sub _build_authoritative_delegate_payload {
  my (%args) = @_;
  return encode_base64(
    encode_json(
      _build_authoritative_delegate_event_hash(%args)
    ),
    '',
  );
}

sub _write_authenticate_payload {
  my ($client, $payload) = @_;
  my $remaining = defined $payload ? $payload : '';
  my $sent = 0;

  while (length($remaining) > 400) {
    _write_client_line($client, 'AUTHENTICATE ' . substr($remaining, 0, 400, ''));
    $sent = 1;
  }

  if (length $remaining) {
    _write_client_line($client, 'AUTHENTICATE ' . $remaining);
    return 1;
  }

  _write_client_line($client, $sent ? 'AUTHENTICATE +' : 'AUTHENTICATE +');
  return 1;
}

sub _read_authenticate_payload {
  my ($client, $timeout_ms) = @_;
  my $payload = '';

  while (1) {
    my $line = _read_client_line($client, $timeout_ms);
    like $line, qr/\A(?::[^ ]+ )?AUTHENTICATE (.+)\z/,
      'server emits an AUTHENTICATE challenge line';
    my ($chunk) = $line =~ /\A(?::[^ ]+ )?AUTHENTICATE (.+)\z/;
    last if !defined($chunk) || $chunk eq '+';
    $payload .= $chunk;
    last if length($chunk) < 400;
  }

  return decode_json(decode_base64($payload));
}

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
    '--grant-kind', _authoritative_grant_kind(),
  );

  close $stdin;
  return {
    pid       => $pid,
    stdout    => $stdout,
    stderr    => $stderr,
    port      => $args{port},
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
  my $relay_url = $args{relay_url};
  my $event_hash = $args{event};
  my $event = Net::Nostr::Event->from_wire($event_hash);
  my $client = Net::Nostr::Client->new;
  my $cv = AnyEvent->condvar;

  $client->on(ok => sub {
    my ($event_id, $accepted, $message) = @_;
    return unless $event_id eq $event->id;
    $cv->send({
      accepted => $accepted ? 1 : 0,
      message  => $message,
    });
  });

  $client->connect($relay_url);
  $client->publish($event);
  my $result = $cv->recv;
  $client->disconnect;

  return $result;
}

sub _query_nostr_events_from_relay {
  my (%args) = @_;
  return Overnet::Core::Nostr->query_events(
    relay_url => $args{relay_url},
    filters   => $args{filters},
    (defined($args{timeout_ms}) ? (timeout_ms => $args{timeout_ms}) : ()),
  );
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

sub _decode_e2ee_transport_from_line {
  my ($line) = @_;
  my $body = _extract_trailing_text($line);
  return undef unless defined $body;
  return undef unless $body =~ /\A\+overnet-e2ee-v1\s+(.+)\z/;

  my $decoded = decode_base64($1);
  return decode_json($decoded);
}

sub _find_emitted_item {
  my ($items, %args) = @_;

  for my $item (@{$items}) {
    next if defined $args{item_type} && ($item->{item_type} || '') ne $args{item_type};
    next unless ref($item->{data}) eq 'HASH';

    if (ref($item->{data}{tags}) eq 'ARRAY') {
      my %tags = _first_tag_values($item->{data}{tags});
      next if defined $args{overnet_et} && ($tags{overnet_et} || '') ne $args{overnet_et};
      next if defined $args{overnet_ot} && ($tags{overnet_ot} || '') ne $args{overnet_ot};
      next if defined $args{overnet_oid} && ($tags{overnet_oid} || '') ne $args{overnet_oid};
    } else {
      next if defined $args{overnet_et} && (($item->{data}{private_type} || '') ne $args{overnet_et});
      next if defined $args{overnet_ot} && (($item->{data}{object_type} || '') ne $args{overnet_ot});
      next if defined $args{overnet_oid} && (($item->{data}{object_id} || '') ne $args{overnet_oid});
    }

    return $item;
  }

  return undef;
}

sub _count_emitted_items {
  my ($items, %args) = @_;
  my $count = 0;

  for my $item (@{$items}) {
    next if defined $args{item_type} && ($item->{item_type} || '') ne $args{item_type};
    next unless ref($item->{data}) eq 'HASH';

    if (ref($item->{data}{tags}) eq 'ARRAY') {
      my %tags = _first_tag_values($item->{data}{tags});
      next if defined $args{overnet_et} && ($tags{overnet_et} || '') ne $args{overnet_et};
      next if defined $args{overnet_ot} && ($tags{overnet_ot} || '') ne $args{overnet_ot};
      next if defined $args{overnet_oid} && ($tags{overnet_oid} || '') ne $args{overnet_oid};
    } else {
      next if defined $args{overnet_et} && (($item->{data}{private_type} || '') ne $args{overnet_et});
      next if defined $args{overnet_ot} && (($item->{data}{object_type} || '') ne $args{overnet_ot});
      next if defined $args{overnet_oid} && (($item->{data}{object_id} || '') ne $args{overnet_oid});
    }

    $count++;
  }

  return $count;
}

sub _assert_signed_emitted_matches_fixture {
  my ($item, $expected, $key, $label, $time_window, $content_override) = @_;
  my $data = $item->{data};
  my $expected_content = defined $content_override
    ? $content_override
    : decode_json($expected->{content});

  like $data->{id}, qr/\A[0-9a-f]{64}\z/, "$label has a signed event id";
  like $data->{sig}, qr/\A[0-9a-f]{128}\z/, "$label has a Schnorr signature";
  is $data->{pubkey}, $key->pubkey_hex, "$label is signed by the configured key";
  is $data->{kind}, $expected->{kind}, "$label kind matches fixture";
  cmp_ok $data->{created_at}, '>=', $time_window->{min}, "$label created_at is not before send time";
  cmp_ok $data->{created_at}, '<=', $time_window->{max}, "$label created_at is within the send window";
  is_deeply $data->{tags}, $expected->{tags}, "$label tags match fixture";
  is_deeply decode_json($data->{content}), $expected_content,
    "$label content matches fixture semantically";

  my $event = Net::Nostr::Event->from_wire($data);
  ok eval { $event->validate; 1 }, "$label validates as a signed Nostr event";
}

sub _assert_private_message_emitted_matches_fixture {
  my ($item, %args) = @_;
  my $label = $args{label} || 'private message';
  my $expected_content = $args{content};
  my $expected_type = $args{private_type};
  my $expected_object_id = $args{object_id};

  my $data = $item->{data};
  is $data->{private_type}, $expected_type, "$label keeps the logical private type";
  is $data->{object_type}, 'chat.dm', "$label keeps the logical object type";
  is $data->{object_id}, $expected_object_id, "$label keeps the logical object id";

  is $data->{transport}{kind}, 1059, "$label uses a kind 1059 gift wrap transport";
  like $data->{transport}{id}, qr/\A[0-9a-f]{64}\z/, "$label has a visible wrap id";
  like $data->{transport}{sig}, qr/\A[0-9a-f]{128}\z/, "$label has a visible wrap signature";
  my $wrap = Net::Nostr::Event->from_wire($data->{transport});
  ok eval { $wrap->validate; 1 }, "$label validates as a signed gift wrap";

  is $data->{decrypted_rumor}{kind}, 14, "$label uses a kind 14 rumor";
  like $data->{decrypted_rumor}{id}, qr/\A[0-9a-f]{64}\z/, "$label has a rumor id";
  is_deeply $data->{decrypted_rumor}{content}, $expected_content,
    "$label decrypted rumor content matches the expected logical payload";

  my @recipient_tags = grep {
    ref($_) eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p'
  } @{$data->{decrypted_rumor}{tags} || []};
  is scalar @recipient_tags, 1, "$label rumor has exactly one recipient tag";
  like $recipient_tags[0][1], qr/\A[0-9a-f]{64}\z/, "$label rumor recipient tag contains a hex pubkey";
}

sub _assert_opaque_private_message_metadata {
  my ($item, %args) = @_;
  my $label = $args{label} || 'opaque private message';
  my $expected_type = $args{private_type};
  my $expected_object_id = $args{object_id};
  my $expected_sender_identity = $args{sender_identity};

  my $data = $item->{data};
  is $data->{private_type}, $expected_type, "$label keeps the logical private type";
  is $data->{object_type}, 'chat.dm', "$label keeps the logical object type";
  is $data->{object_id}, $expected_object_id, "$label keeps the logical object id";
  is $data->{sender_identity}, $expected_sender_identity, "$label keeps sender identity metadata";

  ok !exists($data->{decrypted_rumor}), "$label does not expose decrypted_rumor";
  is $data->{transport}{kind}, 1059, "$label uses a kind 1059 gift wrap transport";
  like $data->{transport}{id}, qr/\A[0-9a-f]{64}\z/, "$label has a visible wrap id";
  like $data->{transport}{sig}, qr/\A[0-9a-f]{128}\z/, "$label has a visible wrap signature";
  my $wrap = Net::Nostr::Event->from_wire($data->{transport});
  ok eval { $wrap->validate; 1 }, "$label validates as a signed gift wrap";

  my @recipient_tags = grep {
    ref($_) eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p'
  } @{$data->{transport}{tags} || []};
  is scalar @recipient_tags, 1, "$label visible transport has exactly one recipient tag";
  like $recipient_tags[0][1], qr/\A[0-9a-f]{64}\z/, "$label visible recipient tag contains a hex pubkey";
}

{
  package Local::MockAuthoritativeIRCAdapter;

  use strict;
  use warnings;

  sub new {
    return bless {
      sessions => {},
    }, shift;
  }

  sub open_session {
    my ($self, %args) = @_;
    my $config = ref($args{session_config}) eq 'HASH'
      ? $args{session_config}
      : {};
    my %channels;

    for my $channel (keys %{$config->{mock_authoritative_channels} || {}}) {
      my $source = $config->{mock_authoritative_channels}{$channel} || {};
      my %members;
      for my $member (@{$source->{members} || []}) {
        next unless ref($member) eq 'HASH';
        next unless defined $member->{pubkey};
        $members{$member->{pubkey}} = {
          pubkey => $member->{pubkey},
          roles  => [ @{$member->{roles} || []} ],
        };
      }

      $channels{$channel} = {
        closed           => $source->{closed} ? 1 : 0,
        moderated        => $source->{moderated} ? 1 : 0,
        topic_restricted => $source->{topic_restricted} ? 1 : 0,
        (exists $source->{topic} ? (topic => $source->{topic}) : ()),
        (exists $source->{topic_actor_pubkey} ? (topic_actor_pubkey => $source->{topic_actor_pubkey}) : ()),
        members          => \%members,
        present          => {},
      };
    }

    $self->{sessions}{$args{adapter_session_id}} = {
      network  => $config->{network},
      channels => \%channels,
    };

    return { accepted => 1 };
  }

  sub close_session {
    my ($self, %args) = @_;
    delete $self->{sessions}{$args{adapter_session_id}};
    return 1;
  }

  sub map_input {
    my ($self, %args) = @_;
    my $session = $self->{sessions}{$args{adapter_session_id}} || {};
    my $channel = $args{target};

    return { valid => 1 }
      unless ($args{session_config}{authority_profile} || '') eq 'nip29';
    return { valid => 1 }
      unless defined $channel && exists $session->{channels}{$channel};

    my $state = $session->{channels}{$channel};
    if (($args{command} || '') eq 'MODE') {
      my $mode = $args{mode} || '';
      if ($mode =~ /\A([+-])([ov])\z/) {
        my ($direction, $mode_letter) = ($1, $2);
        my $target_pubkey = $args{target_pubkey};
        my %roles = map { $_ => 1 } @{$args{current_roles} || []};
        my $role_name = $mode_letter eq 'o' ? 'irc.operator' : 'irc.voice';
        if ($direction eq '+') {
          $roles{$role_name} = 1;
        } else {
          delete $roles{$role_name};
        }
        $state->{members}{$target_pubkey} = {
          pubkey => $target_pubkey,
          roles  => [ sort keys %roles ],
        };
        return { valid => 1 };
      }

      if ($mode =~ /\A([+-])([imt])\z/) {
        my ($direction, $mode_letter) = ($1, $2);
        my $enabled = $direction eq '+' ? 1 : 0;
        $state->{closed} = $enabled if $mode_letter eq 'i';
        $state->{moderated} = $enabled if $mode_letter eq 'm';
        $state->{topic_restricted} = $enabled if $mode_letter eq 't';
        return { valid => 1 };
      }
    }

    if (($args{command} || '') eq 'KICK') {
      if (defined $args{target_pubkey}) {
        delete $state->{members}{$args{target_pubkey}};
        delete $state->{present}{$args{target_pubkey}};
      }
      return { valid => 1 };
    }

    if (($args{command} || '') eq 'JOIN') {
      $state->{present}{$args{actor_pubkey}} = 1
        if defined $args{actor_pubkey};
      return { valid => 1 };
    }

    if (($args{command} || '') eq 'PART') {
      if (defined $args{actor_pubkey}) {
        delete $state->{members}{$args{actor_pubkey}};
        delete $state->{present}{$args{actor_pubkey}};
      }
      return { valid => 1 };
    }

    if (($args{command} || '') eq 'TOPIC') {
      if (defined $args{text}) {
        $state->{topic} = $args{text};
        $state->{topic_actor_pubkey} = $args{actor_pubkey}
          if defined $args{actor_pubkey};
      } else {
        delete $state->{topic};
        delete $state->{topic_actor_pubkey};
      }
      return { valid => 1 };
    }

    return { valid => 1 };
  }

  sub derive {
    my ($self, %args) = @_;
    my $session = $self->{sessions}{$args{adapter_session_id}} || {};
    my $operation = $args{operation} || '';
    my $input = ref($args{input}) eq 'HASH' ? $args{input} : {};
    my $channel = $input->{target};
    my $state = $session->{channels}{$channel} || {
      closed           => 0,
      moderated        => 0,
      topic_restricted => 0,
      tombstoned       => 0,
      ban_masks        => [],
      members          => {},
    };

    my $channel_modes = '+' . join(
      '',
      grep { $_ }
        ($state->{closed} ? 'i' : ''),
        ($state->{moderated} ? 'm' : ''),
        'n',
        ($state->{topic_restricted} ? 't' : ''),
    );

    my @members = map {
      my $member = $state->{members}{$_};
      my @roles = sort @{$member->{roles} || []};
      {
        pubkey                => $member->{pubkey},
        roles                 => \@roles,
        presentational_prefix => (
          (grep { $_ eq 'irc.operator' } @roles) ? '@'
            : (grep { $_ eq 'irc.voice' } @roles) ? '+'
            : ''
        ),
      }
    } sort keys %{$state->{members} || {}};

    if ($operation eq 'authoritative_channel_view') {
      my @present_members = map {
        my $member = $state->{members}{$_};
        my @roles = sort @{$member->{roles} || []};
        {
          pubkey                => $member->{pubkey},
          roles                 => \@roles,
          presentational_prefix => (
            (grep { $_ eq 'irc.operator' } @roles) ? '@'
              : (grep { $_ eq 'irc.voice' } @roles) ? '+'
              : ''
          ),
        }
      } grep {
        exists $state->{members}{$_}
      } sort keys %{$state->{present} || {}};
      my $admission = {
        allowed => JSON::PP::false,
        member  => JSON::PP::false,
        reason  => $state->{closed} ? '+i' : '',
      };
      if (defined $input->{actor_pubkey} && exists $state->{members}{$input->{actor_pubkey}}) {
        $admission = {
          allowed => JSON::PP::true,
          member  => JSON::PP::true,
          reason  => '',
        };
      }

      return {
        valid => 1,
        view  => [
          {
            operation         => 'authoritative_channel_view',
            authority_profile => 'nip29',
            object_type       => 'chat.channel',
            object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
            channel_modes     => $channel_modes,
            (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
            (exists($state->{topic_actor_pubkey}) ? (topic_actor_pubkey => $state->{topic_actor_pubkey}) : ()),
            supported_roles   => [],
            members           => \@members,
            present_members   => \@present_members,
            pending_invites   => [],
            admission         => $admission,
          },
        ],
      };
    }

    if ($operation eq 'authoritative_join_admission') {
      my $admission = {
        operation         => 'authoritative_join_admission',
        authority_profile => 'nip29',
        object_type       => 'chat.channel',
        object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
        allowed           => JSON::PP::false,
        member            => JSON::PP::false,
        present           => JSON::PP::false,
        create_channel    => JSON::PP::false,
        auth_required     => defined($input->{actor_pubkey}) ? JSON::PP::false : JSON::PP::true,
        reason            => defined($input->{actor_pubkey}) ? ($state->{closed} ? '+i' : '') : 'auth_required',
      };
      if (defined $input->{actor_pubkey} && exists $state->{members}{$input->{actor_pubkey}}) {
        $admission = {
          %{$admission},
          allowed => JSON::PP::true,
          member  => JSON::PP::true,
          reason  => '',
        };
      }
      if (defined $input->{actor_pubkey} && exists $state->{present}{$input->{actor_pubkey}}) {
        $admission->{present} = JSON::PP::true;
      }

      return {
        valid     => 1,
        admission => [ $admission ],
      };
    }

    if ($operation eq 'authoritative_speak_permission') {
      my $member = defined $input->{actor_pubkey}
        ? $state->{members}{$input->{actor_pubkey}}
        : undef;
      my @roles = ref($member) eq 'HASH' ? sort @{$member->{roles} || []} : ();
      my %roles = map { $_ => 1 } @roles;
      return {
        valid      => 1,
        permission => [
          {
            operation         => 'authoritative_speak_permission',
            authority_profile => 'nip29',
            object_type       => 'chat.channel',
            object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
            allowed           => (!$state->{moderated} || $roles{'irc.operator'} || $roles{'irc.voice'})
              ? JSON::PP::true
              : JSON::PP::false,
            roles             => \@roles,
            presentational_prefix => $roles{'irc.operator'} ? '@' : $roles{'irc.voice'} ? '+' : '',
            reason            => (!$state->{moderated} || $roles{'irc.operator'} || $roles{'irc.voice'}) ? '' : '+m',
          },
        ],
      };
    }

    if ($operation eq 'authoritative_topic_permission') {
      my $member = defined $input->{actor_pubkey}
        ? $state->{members}{$input->{actor_pubkey}}
        : undef;
      my @roles = ref($member) eq 'HASH' ? sort @{$member->{roles} || []} : ();
      my %roles = map { $_ => 1 } @roles;
      return {
        valid      => 1,
        permission => [
          {
            operation         => 'authoritative_topic_permission',
            authority_profile => 'nip29',
            object_type       => 'chat.channel',
            object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
            allowed           => (!$state->{topic_restricted} || $roles{'irc.operator'})
              ? JSON::PP::true
              : JSON::PP::false,
            reason            => (!$state->{topic_restricted} || $roles{'irc.operator'}) ? '' : '+t',
          },
        ],
      };
    }

    if ($operation eq 'authoritative_mode_write_permission') {
      my $member = defined $input->{actor_pubkey}
        ? $state->{members}{$input->{actor_pubkey}}
        : undef;
      my @roles = ref($member) eq 'HASH' ? sort @{$member->{roles} || []} : ();
      my %roles = map { $_ => 1 } @roles;
      my $mode = $input->{mode} || '';
      my $mode_args = ref($input->{mode_args}) eq 'ARRAY' ? $input->{mode_args} : [];
      my %permission = (
        operation         => 'authoritative_mode_write_permission',
        authority_profile => 'nip29',
        object_type       => 'chat.channel',
        object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
        allowed           => $state->{tombstoned}
          ? JSON::PP::false
          : $roles{'irc.operator'} ? JSON::PP::true : JSON::PP::false,
        mode              => $mode,
        reason            => $state->{tombstoned}
          ? 'deleted'
          : $roles{'irc.operator'} ? '' : 'not_operator',
      );
      if (!$state->{tombstoned} && $roles{'irc.operator'}) {
        if ($mode =~ /\A[+-][ov]\z/ && defined($mode_args->[0])) {
          my $target_member = $state->{members}{$mode_args->[0]};
          $permission{target_pubkey} = $mode_args->[0];
          $permission{current_roles} = ref($target_member) eq 'HASH'
            ? [ sort @{$target_member->{roles} || []} ]
            : [];
        } elsif ($mode =~ /\A[+-][b]\z/ && defined($mode_args->[0])) {
          $permission{normalized_ban_mask} = $mode_args->[0];
          $permission{group_metadata} = {
            closed           => $state->{closed} ? 1 : 0,
            moderated        => $state->{moderated} ? 1 : 0,
            topic_restricted => $state->{topic_restricted} ? 1 : 0,
            ban_masks        => [ @{$state->{ban_masks} || []} ],
            tombstoned       => 0,
            (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
          };
        } elsif ($mode =~ /\A[+-][imt]\z/) {
          $permission{group_metadata} = {
            closed           => $state->{closed} ? 1 : 0,
            moderated        => $state->{moderated} ? 1 : 0,
            topic_restricted => $state->{topic_restricted} ? 1 : 0,
            ban_masks        => [ @{$state->{ban_masks} || []} ],
            tombstoned       => 0,
            (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
          };
        }
      }
      return {
        valid      => 1,
        permission => [ \%permission ],
      };
    }

    if ($operation eq 'authoritative_channel_action_permission') {
      my $member = defined $input->{actor_pubkey}
        ? $state->{members}{$input->{actor_pubkey}}
        : undef;
      my @roles = ref($member) eq 'HASH' ? sort @{$member->{roles} || []} : ();
      my %roles = map { $_ => 1 } @roles;
      my $action = $input->{action} || '';
      my %permission = (
        operation         => 'authoritative_channel_action_permission',
        authority_profile => 'nip29',
        object_type       => 'chat.channel',
        object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
        action            => $action,
        allowed           => JSON::PP::false,
        reason            => '',
      );
      if ($action eq 'undelete') {
        $permission{reason} = !$state->{tombstoned}
          ? 'not_deleted'
          : $roles{'irc.operator'} ? '' : 'not_operator';
        $permission{allowed} = ($state->{tombstoned} && $roles{'irc.operator'})
          ? JSON::PP::true
          : JSON::PP::false;
      } else {
        $permission{reason} = $state->{tombstoned}
          ? 'deleted'
          : $roles{'irc.operator'} ? '' : 'not_operator';
        $permission{allowed} = (!$state->{tombstoned} && $roles{'irc.operator'})
          ? JSON::PP::true
          : JSON::PP::false;
      }
      if ($permission{allowed}) {
        $permission{target_pubkey} = $input->{target_pubkey}
          if defined $input->{target_pubkey};
        if ($action eq 'delete' || $action eq 'undelete') {
          $permission{group_metadata} = {
            closed           => $state->{closed} ? 1 : 0,
            moderated        => $state->{moderated} ? 1 : 0,
            topic_restricted => $state->{topic_restricted} ? 1 : 0,
            ban_masks        => [ @{$state->{ban_masks} || []} ],
            tombstoned       => $state->{tombstoned} ? 1 : 0,
            (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
          };
        }
      }
      return {
        valid      => 1,
        permission => [ \%permission ],
      };
    }

    return {
      valid => 1,
      state => [
        {
          operation         => 'authoritative_channel_state',
          authority_profile => 'nip29',
          object_type       => 'chat.channel',
          object_id         => 'irc:' . ($session->{network} || 'irc.test') . ':' . $channel,
          channel_modes     => $channel_modes,
          (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
          (exists($state->{topic_actor_pubkey}) ? (topic_actor_pubkey => $state->{topic_actor_pubkey}) : ()),
          members           => \@members,
        },
      ],
    };
  }
}

subtest 'IRC server program enforces nick uniqueness and emits 433 for collisions' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $network_object_id = 'irc:' . $privmsg->{input}{network};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for nick-collision coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'nick-collision server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'nick-collision server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'nick-collision server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});
  my $carol = _connect_irc_client($ready_details->{listen_port});
  my $dave  = _connect_irc_client($ready_details->{listen_port});
  my $erin  = _connect_irc_client($ready_details->{listen_port});
  my $frank = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($bob, 'NICK alice');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 * alice :Nickname is already in use',
    'unregistered nick collision returns 433 with * target';

  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes the first DM subscription open';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes the second DM subscription open';

  _write_client_line($bob, 'NICK alice');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 bob alice :Nickname is already in use',
    'registered nick collision returns 433 with the current nick target';

  _write_client_line($alice, 'NICK alice_');
  is _read_client_line($alice, 1_000), ':alice NICK :alice_',
    'successful nick change is rendered back to the client';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'irc.nick',
        overnet_ot  => 'irc.network',
        overnet_oid => $network_object_id,
      );
    },
  ), 'successful nick change is emitted through the runtime';

  _write_client_line($carol, 'NICK alice');
  _write_client_line($carol, 'USER carol 0 * :Carol Example');
  _assert_registration_prelude(
    client  => $carol,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 3),
    'carol registration completes its DM subscription open';

  _write_client_line($bob, 'QUIT :bye');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.close',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= 2;
    },
  ), 'bob quit completes its DM subscription close';
  my $bob_closed = eval {
    _read_client_line($bob, 500);
    '';
  };
  like $@, qr/IRC client disconnected before sending a line/,
    'server closes the client connection after QUIT';

  _write_client_line($dave, 'NICK bob');
  _write_client_line($dave, 'USER dave 0 * :Dave Example');
  _assert_registration_prelude(
    client  => $dave,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 5),
    'dave registration completes its DM subscription open';

  _write_client_line($erin, 'NICK erin');
  close $erin->{socket};
  ok $host->pump(timeout_ms => 200) >= 0,
    'server continues running after an unregistered client disconnects';
  _write_client_line($frank, 'NICK erin');
  _write_client_line($frank, 'USER frank 0 * :Frank Example');
  _assert_registration_prelude(
    client  => $frank,
    nick    => 'erin',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 6),
    'frank registration completes its DM subscription open';

  is _method_count($host->transcript, 'from_program', 'request', 'adapters.map_input'), 1,
    'only the successful registered nick change reaches adapter mapping';

  my $shutdown = $host->request_shutdown(reason => 'nick collision test complete');
  is $shutdown->{state}, 'shutdown_complete', 'nick-collision server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'nick-collision server exits cleanly';

  close $alice->{socket};
  close $carol->{socket};
  close $dave->{socket};
  close $frank->{socket};
};

subtest 'IRC server program supports a minimal IRC client compatibility slice' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $network = $privmsg->{input}{network};
  my $channel_object_id = 'irc:' . $network . ':#OverNet';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for compatibility coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'compatibility server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'compatibility server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'compatibility server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'CAP LS 302');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * LS :message-tags server-time overnet-e2ee',
    'CAP LS advertises the IRCv3 tag/time capabilities alongside overnet-e2ee';

  _write_client_line($alice, 'CAP REQ :overnet-e2ee');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * ACK :overnet-e2ee',
    'CAP REQ ACKs the supported overnet-e2ee capability';

  _write_client_line($alice, 'CAP REQ :multi-prefix sasl');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * NAK :multi-prefix sasl',
    'CAP REQ returns NAK for unsupported capabilities';

  _write_client_line($alice, 'CAP END');
  is _read_client_line_optional($alice, 200), undef,
    'CAP END does not emit any compatibility reply';

  _write_client_line($alice, 'JOIN #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration JOIN returns 451';

  _write_client_line($alice, 'MODE #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration MODE returns 451';

  _write_client_line($alice, 'USERHOST Alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration USERHOST returns 451';

  _write_client_line($alice, 'WHO #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration WHO returns 451';

  _write_client_line($alice, 'WHOIS Alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration WHOIS returns 451';

  _write_client_line($alice, 'LUSERS');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration LUSERS returns 451';

  _write_client_line($alice, 'LIST');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration LIST returns 451';

  _write_client_line($alice, 'NICK');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 431 * :No nickname given',
    'bare NICK returns 431';

  _write_client_line($alice, 'USER alice 0 *');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 * USER :Not enough parameters',
    'short USER returns 461';

  _write_client_line($alice, 'NICK Alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'Alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open';

  _write_client_line($alice, 'LUSERS');
  is_deeply [
    _read_client_lines($alice, 5, 1_000),
  ], [
    ':overnet.irc.local 251 Alice :There are 1 users and 0 services on 1 server',
    ':overnet.irc.local 252 Alice 0 :operator(s) online',
    ':overnet.irc.local 253 Alice 0 :unknown connection(s)',
    ':overnet.irc.local 254 Alice 0 :channels formed',
    ':overnet.irc.local 255 Alice :I have 2 clients and 1 server',
  ], 'LUSERS returns the minimal reply set';

  _write_client_line($alice, 'USERHOST');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice USERHOST :Not enough parameters',
    'USERHOST without a nick returns 461';

  _write_client_line($alice, 'WHO');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice WHO :Not enough parameters',
    'WHO without a target returns 461';

  _write_client_line($alice, 'WHOIS');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice WHOIS :Not enough parameters',
    'WHOIS without a nick returns 461';

  _write_client_line($alice, 'TOPIC');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice TOPIC :Not enough parameters',
    'TOPIC without a target returns 461';

  _write_client_line($alice, 'USERHOST aLiCe');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 302 Alice :Alice=+alice@127.0.0.1',
    'USERHOST uses folded nick lookup and returns a minimal 302 reply';

  _write_client_line($alice, 'WHOIS aLiCe');
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':overnet.irc.local 311 Alice Alice alice 127.0.0.1 * :Alice Example',
    ':overnet.irc.local 312 Alice Alice overnet.irc.local :Overnet IRC',
    ':overnet.irc.local 318 Alice Alice :End of /WHOIS list.',
  ], 'WHOIS uses folded nick lookup and returns minimal WHOIS replies';

  _write_client_line($alice, 'FROB');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 421 Alice FROB :Unknown command',
    'unknown registered commands return 421';

  _write_client_line($alice, 'PART #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'PART on an unjoined channel returns 442';

  _write_client_line($alice, 'MODE');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice MODE :Not enough parameters',
    'MODE without a target returns 461';

  _write_client_line($alice, 'MODE aLiCe');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 221 Alice +',
    'self MODE query uses folded nick lookup and returns a minimal user mode reply';

  _write_client_line($alice, 'MODE #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'MODE on an unjoined channel returns 442';

  _write_client_line($alice, 'WHO #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'WHO on an unjoined channel returns 442';

  _write_client_line($alice, 'TOPIC #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'TOPIC query on an unjoined channel returns 442';

  _write_client_line($alice, 'JOIN alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 403 Alice alice :No such channel',
    'JOIN on a non-channel target returns 403';

  _write_client_line($alice, 'PRIVMSG MissingNick :hello');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 401 Alice MissingNick :No such nick/channel',
    'PRIVMSG to a missing nick returns 401';

  _write_client_line($alice, 'WHOIS MissingNick');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 401 Alice MissingNick :No such nick/channel',
    'WHOIS for a missing nick returns 401';

  _write_client_line($bob, 'NICK aLICE');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 * aLICE :Nickname is already in use',
    'nick uniqueness uses RFC1459-style case-folding';

  _write_client_line($alice, 'JOIN #OverNet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'case-folded JOIN is emitted on the canonical channel object';
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':Alice JOIN #OverNet',
    ':overnet.irc.local 353 Alice = #OverNet :Alice',
    ':overnet.irc.local 366 Alice #OverNet :End of /NAMES list.',
  ], 'join preserves the first presentational channel spelling and returns bootstrap lines';

  _write_client_line($alice, 'MODE #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 324 Alice #OverNet +n',
    'MODE query uses folded channel lookup and canonical channel spelling';

  _write_client_line($alice, 'NAMES #oVERnEt');
  is_deeply [
    _read_client_lines($alice, 2, 1_000),
  ], [
    ':overnet.irc.local 353 Alice = #OverNet :Alice',
    ':overnet.irc.local 366 Alice #OverNet :End of /NAMES list.',
  ], 'explicit NAMES uses the canonical channel spelling after case-folded lookup';

  _write_client_line($alice, 'TOPIC #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 331 Alice #OverNet :No topic is set',
    'TOPIC query returns 331 when no topic is known';

  _write_client_line($alice, 'WHO #oVERnEt');
  is_deeply [
    _read_client_lines($alice, 2, 1_000),
  ], [
    ':overnet.irc.local 352 Alice #OverNet alice 127.0.0.1 overnet.irc.local Alice H :0 Alice Example',
    ':overnet.irc.local 315 Alice #OverNet :End of /WHO list.',
  ], 'WHO query uses folded channel lookup and returns minimal WHO replies';

  _write_client_line($alice, 'PRIVMSG #oVERnEt :Casefolded hello');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.message',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'case-folded channel PRIVMSG is emitted on the canonical channel object';
  is _read_client_line($alice, 1_000), ':Alice PRIVMSG #OverNet :Casefolded hello',
    'case-folded channel PRIVMSG renders back using the canonical channel spelling';

  _write_client_line($alice, 'TOPIC #oVERnEt :Compatibility topic');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'state',
        overnet_et  => 'chat.topic',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TOPIC set in compatibility coverage is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':Alice TOPIC #OverNet :Compatibility topic',
    'TOPIC set renders back through the subscription path';

  _write_client_line($alice, 'TOPIC #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 332 Alice #OverNet :Compatibility topic',
    'TOPIC query returns 332 when a topic is known';

  _write_client_line($alice, 'LIST');
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':overnet.irc.local 321 Alice Channel :Users Name',
    ':overnet.irc.local 322 Alice #OverNet 1 :Compatibility topic',
    ':overnet.irc.local 323 Alice :End of /LIST',
  ], 'LIST returns the current exposed channel state';

  my $shutdown = $host->request_shutdown(reason => 'compatibility test complete');
  is $shutdown->{state}, 'shutdown_complete', 'compatibility server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'compatibility server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program accepts clients, emits Overnet output, and fans channel items back out' => sub {
  my $join = _load_irc_fixture('valid-channel-join.json');
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $part = _load_irc_fixture('valid-channel-part.json');
  my $quit = _load_irc_fixture('valid-channel-quit.json');
  my $nick = _load_irc_fixture('valid-network-nick.json');
  my $topic = _load_irc_fixture('valid-channel-topic.json');
  my $channel_object_id = 'irc:' . $privmsg->{input}{network} . ':' . $privmsg->{input}{target};
  my $network_object_id = 'irc:' . $privmsg->{input}{network};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for the program';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'program reaches ready state under Host supervision';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'program publishes ready health details';
  is $ready_details->{server_name}, 'overnet.irc.local', 'ready health exposes configured server name';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'ready health exposes the bound listen port';

  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub { scalar(@{$runtime->adapter_session_ids}) == 1 },
  ), 'program opens a long-lived IRC adapter session after startup';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes the first DM subscription open';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes the second DM subscription open';

  _write_client_line($alice, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.join',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice join is emitted through the runtime';
  is_deeply [
    _read_client_lines($alice, 3, 1_000)
  ], [
    ':alice JOIN #overnet',
    ':overnet.irc.local 353 alice = #overnet :alice',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
  ], 'alice receives JOIN plus the minimal NAMES bootstrap';

  my $privmsg_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'PRIVMSG #overnet :Hello from IRC!');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.message',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice channel message is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice PRIVMSG #overnet :Hello from IRC!',
    'alice receives the subscription-driven PRIVMSG render';
  is _read_client_line_optional($bob, 200), undef,
    'bob does not receive channel renders before joining the channel';

  _write_client_line($bob, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _count_emitted_items(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      ) >= 2;
    },
  ), 'bob join is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':bob JOIN #overnet',
    'joined clients receive later join lines';
  is_deeply [
    _read_client_lines($bob, 3, 1_000)
  ], [
    ':bob JOIN #overnet',
    ':overnet.irc.local 353 bob = #overnet :alice bob',
    ':overnet.irc.local 366 bob #overnet :End of /NAMES list.',
  ], 'joining client receives its own join line plus NAMES bootstrap';

  my $topic_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'TOPIC #overnet :Overnet discussion and implementation');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'state',
        overnet_et => 'chat.topic',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob topic update is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':bob TOPIC #overnet :Overnet discussion and implementation',
    'alice receives subscription-driven TOPIC fanout';
  is _read_client_line($bob, 1_000), ':bob TOPIC #overnet :Overnet discussion and implementation',
    'bob receives subscription-driven TOPIC fanout';

  my $carol = _connect_irc_client($ready_details->{listen_port});
  _write_client_line($carol, 'NICK carol');
  _write_client_line($carol, 'USER carol 0 * :Carol Example');
  _assert_registration_prelude(
    client  => $carol,
    nick    => 'carol',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 3),
    'carol registration completes its DM subscription open';

  _write_client_line($carol, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _count_emitted_items(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      ) >= 3;
    },
  ), 'carol join is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':carol JOIN #overnet',
    'existing joined clients receive carol join lines';
  is _read_client_line($bob, 1_000), ':carol JOIN #overnet',
    'all joined clients receive carol join lines';
  is_deeply [
    _read_client_lines($carol, 4, 1_000)
  ], [
    ':carol JOIN #overnet',
    ':bob TOPIC #overnet :Overnet discussion and implementation',
    ':overnet.irc.local 353 carol = #overnet :alice bob carol',
    ':overnet.irc.local 366 carol #overnet :End of /NAMES list.',
  ], 'carol receives join, topic replay, and NAMES bootstrap';

  my $nick_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'NICK alice_');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'irc.nick',
        overnet_ot  => 'irc.network',
        overnet_oid => $network_object_id,
      );
    },
  ), 'alice nick change is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice NICK :alice_',
    'alice receives her own NICK line';
  is _read_client_line($bob, 1_000), ':alice NICK :alice_',
    'bob receives alice nick change';
  is _read_client_line($carol, 1_000), ':alice NICK :alice_',
    'carol receives alice nick change';

  _write_client_line($alice, 'PART #overnet :bye');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.part',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice part is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice_ PART #overnet :bye',
    'alice receives her own PART line';
  is _read_client_line($bob, 1_000), ':alice_ PART #overnet :bye',
    'remaining channel members receive PART lines';
  is _read_client_line($carol, 1_000), ':alice_ PART #overnet :bye',
    'all remaining channel members receive PART lines';

  _write_client_line($bob, 'NOTICE #overnet :Only Bob now');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.notice',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob notice is emitted through the runtime';
  is _read_client_line($bob, 1_000), ':bob NOTICE #overnet :Only Bob now',
    'bob receives subscription-driven NOTICE fanout';
  is _read_client_line($carol, 1_000), ':bob NOTICE #overnet :Only Bob now',
    'carol receives subscription-driven NOTICE fanout';
  is _read_client_line_optional($alice, 200), undef,
    'alice no longer receives renders after parting the channel';

  my $quit_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'QUIT :gone');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.quit',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob quit is emitted through the runtime';
  is _read_client_line($carol, 1_000), ':bob QUIT :gone',
    'remaining shared channel members receive QUIT lines';
  is _read_client_line_optional($alice, 200), undef,
    'parted clients do not receive later QUIT lines';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.close',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= 2;
    },
  ), 'bob quit completes its DM subscription close before later client input';

  _write_client_line($carol, 'PART #overnet :done');
  is _read_client_line($carol, 1_000), ':carol PART #overnet :done',
    'carol receives her own final PART line';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _method_count($_[0]->transcript, 'from_program', 'request', 'subscriptions.close') >= 1
        && _count_emitted_items(
          $_[0]->runtime->emitted_items,
          item_type   => 'event',
          overnet_et  => 'chat.part',
          overnet_ot  => 'chat.channel',
          overnet_oid => $channel_object_id,
        ) >= 2;
    },
  ), 'program completes the final PART emit flow and closes the runtime subscription';

  my $emitted = $runtime->emitted_items;
  is _count_emitted_items(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.join',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  ), 3, 'runtime recorded three channel join events';
  my $message_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.message',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $message_item, 'runtime recorded the channel message event';
  _assert_signed_emitted_matches_fixture(
    $message_item,
    $privmsg->{expected}{event},
    $key,
    'mapped channel PRIVMSG event',
    $privmsg_window,
  );

  my $topic_item = _find_emitted_item(
    $emitted,
    item_type   => 'state',
    overnet_et  => 'chat.topic',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $topic_item, 'runtime recorded the channel topic state';
  my $topic_expected_content = decode_json($topic->{expected}{event}{content});
  $topic_expected_content->{provenance}{external_identity} = 'bob';
  _assert_signed_emitted_matches_fixture(
    $topic_item,
    $topic->{expected}{event},
    $key,
    'mapped channel TOPIC state',
    $topic_window,
    $topic_expected_content,
  );

  my $notice_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.notice',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $notice_item, 'runtime recorded the channel notice event';
  my $notice_event = Net::Nostr::Event->from_wire($notice_item->{data});
  ok eval { $notice_event->validate; 1 }, 'mapped channel notice validates as a signed Nostr event';

  my $nick_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'irc.nick',
    overnet_ot  => 'irc.network',
    overnet_oid => $network_object_id,
  );
  ok $nick_item, 'runtime recorded the network nick event';
  _assert_signed_emitted_matches_fixture(
    $nick_item,
    $nick->{expected}{event},
    $key,
    'mapped network NICK event',
    $nick_window,
  );

  my $part_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.part',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $part_item, 'runtime recorded the channel part event';
  my $part_expected_content = decode_json($part->{expected}{event}{content});
  $part_expected_content->{provenance}{external_identity} = 'alice_';
  _assert_signed_emitted_matches_fixture(
    $part_item,
    $part->{expected}{event},
    $key,
    'mapped channel PART event',
    {
      min => int(time()) - 10,
      max => int(time()) + 5,
    },
    $part_expected_content,
  );

  my $quit_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.quit',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $quit_item, 'runtime recorded the channel quit event';
  my $quit_expected_content = decode_json($quit->{expected}{event}{content});
  $quit_expected_content->{provenance}{external_identity} = 'bob';
  $quit_expected_content->{body}{reason} = 'gone';
  _assert_signed_emitted_matches_fixture(
    $quit_item,
    $quit->{expected}{event},
    $key,
    'mapped channel QUIT event',
    $quit_window,
    $quit_expected_content,
  );

  my $transcript = $host->transcript;
  is _request_count_matching(
    $transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'program opens one shared channel subscription';
  is _request_count_matching(
    $transcript,
    'from_program',
    'subscriptions.close',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'program closes one shared channel subscription when the channel becomes empty';
  ok _method_count($transcript, 'to_program', 'notification', 'runtime.subscription_event') >= 6,
    'runtime delivers subscription events back to the program';
  ok _method_count($transcript, 'from_program', 'request', 'adapters.map_input') >= 9,
    'program maps client IRC commands through the adapter service';
  ok _method_count($transcript, 'from_program', 'request', 'overnet.emit_event') >= 8,
    'program emits event candidates through the runtime';
  ok _method_count($transcript, 'from_program', 'request', 'overnet.emit_state') >= 1,
    'program emits state candidates through the runtime';

  my $shutdown = $host->request_shutdown(reason => 'test complete');
  is $shutdown->{state}, 'shutdown_complete', 'program handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'program exits cleanly';
  is scalar @{$runtime->adapter_session_ids}, 0, 'runtime releases the long-lived adapter session on process exit';

  close $alice->{socket};
  close $bob->{socket};
  close $carol->{socket};
};

subtest 'IRC server program routes direct messages through directional chat.dm objects' => sub {
  my $dm_privmsg = _load_irc_fixture('valid-dm-privmsg.json');
  my $dm_notice = _load_irc_fixture('valid-dm-notice.json');
  my $network = $dm_privmsg->{input}{network};
  my $bob_dm_object_id = 'irc:' . $network . ':dm:bob';
  my $alice_dm_object_id = 'irc:' . $network . ':dm:alice';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for direct-message coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'direct-message server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'direct-message server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'direct-message server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $dm_privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice DM subscription opens after registration';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $dm_privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'program opens one DM subscription per registered nick';

  my $dm_message_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'PRIVMSG bob :hello in private');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'private_message',
        overnet_et  => 'chat.dm_message',
        overnet_ot  => 'chat.dm',
        overnet_oid => $bob_dm_object_id,
      );
    },
  ), 'alice direct-message PRIVMSG is emitted as an encrypted private message';
  $host->pump(timeout_ms => 100);
  is _read_client_line($bob, 1_000), ':alice PRIVMSG bob :hello in private',
    'bob receives the direct-message PRIVMSG fanout';
  is _read_client_line_optional($alice, 200), undef,
    'sender does not receive a synthetic DM echo';

  my $dm_notice_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'NOTICE alice :private notice');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'private_message',
        overnet_et  => 'chat.dm_notice',
        overnet_ot  => 'chat.dm',
        overnet_oid => $alice_dm_object_id,
      );
    },
  ), 'bob direct-message NOTICE is emitted as an encrypted private message';
  $host->pump(timeout_ms => 100);
  is _read_client_line($alice, 1_000), ':bob NOTICE alice :private notice',
    'alice receives the direct-message NOTICE fanout';
  is _read_client_line_optional($bob, 200), undef,
    'NOTICE sender does not receive a synthetic DM echo';

  my $dm_message_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'private_message',
    overnet_et  => 'chat.dm_message',
    overnet_ot  => 'chat.dm',
    overnet_oid => $bob_dm_object_id,
  );
  ok $dm_message_item, 'runtime recorded the direct-message PRIVMSG private message';
  my $dm_message_content = decode_json($dm_privmsg->{expected}{event}{content});
  $dm_message_content->{provenance}{origin} = $network . '/bob';
  $dm_message_content->{provenance}{external_identity} = 'alice';
  $dm_message_content->{body}{text} = 'hello in private';
  _assert_private_message_emitted_matches_fixture(
    $dm_message_item,
    label        => 'mapped direct-message PRIVMSG',
    private_type => 'chat.dm_message',
    object_id    => $bob_dm_object_id,
    content      => {
      overnet_v    => '0.1.0',
      private_type => 'chat.dm_message',
      object_type  => 'chat.dm',
      object_id    => $bob_dm_object_id,
      provenance   => $dm_message_content->{provenance},
      body         => $dm_message_content->{body},
    },
  );

  my $dm_notice_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'private_message',
    overnet_et  => 'chat.dm_notice',
    overnet_ot  => 'chat.dm',
    overnet_oid => $alice_dm_object_id,
  );
  ok $dm_notice_item, 'runtime recorded the direct-message NOTICE private message';
  my $dm_notice_content = decode_json($dm_notice->{expected}{event}{content});
  $dm_notice_content->{provenance}{origin} = $network . '/alice';
  $dm_notice_content->{provenance}{external_identity} = 'bob';
  $dm_notice_content->{body}{text} = 'private notice';
  _assert_private_message_emitted_matches_fixture(
    $dm_notice_item,
    label        => 'mapped direct-message NOTICE',
    private_type => 'chat.dm_notice',
    object_id    => $alice_dm_object_id,
    content      => {
      overnet_v    => '0.1.0',
      private_type => 'chat.dm_notice',
      object_type  => 'chat.dm',
      object_id    => $alice_dm_object_id,
      provenance   => $dm_notice_content->{provenance},
      body         => $dm_notice_content->{body},
    },
  );

  my $shutdown = $host->request_shutdown(reason => 'direct message test complete');
  is $shutdown->{state}, 'shutdown_complete', 'direct-message server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'direct-message server exits cleanly';
  is _request_count_matching(
    $host->transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
  ), 2, 'program opens exactly two DM subscriptions for the two registered clients';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program blind-routes endpoint-blind E2E direct messages for E2EE-aware clients' => sub {
  my $dm_privmsg = _load_irc_fixture('valid-dm-privmsg.json');
  my $network = $dm_privmsg->{input}{network};
  my $bob_dm_object_id = 'irc:' . $network . ':dm:bob';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $server_key = Net::Nostr::Key->new;
  $server_key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for E2EE direct-message coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.close_session'       => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'E2EE direct-message server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'E2EE direct-message server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'E2EE direct-message server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob = _connect_irc_client($ready_details->{listen_port});
  my $alice_key = Net::Nostr::Key->new;
  my $bob_key = Net::Nostr::Key->new;

  _write_client_line($alice, 'CAP LS 302');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * LS :message-tags server-time overnet-e2ee',
    'alice sees IRCv3 tag/time capabilities alongside overnet-e2ee in CAP LS';
  _write_client_line($alice, 'CAP REQ :overnet-e2ee');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * ACK :overnet-e2ee',
    'alice CAP REQ overnet-e2ee is acknowledged';
  _write_client_line($alice, 'CAP END');
  is _read_client_line_optional($alice, 200), undef, 'alice CAP END produces no extra line';
  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes the first E2EE DM subscription open';
  _write_client_line($alice, 'OVERNETKEY SET ' . $alice_key->pubkey_hex);
  is _read_client_line($alice, 1_000),
    ':overnet.irc.local NOTICE alice :OVERNETKEY SET ' . $alice_key->pubkey_hex,
    'alice registers her E2EE pubkey';

  _write_client_line($bob, 'CAP LS 302');
  is _read_client_line($bob, 1_000), ':overnet.irc.local CAP * LS :message-tags server-time overnet-e2ee',
    'bob sees IRCv3 tag/time capabilities alongside overnet-e2ee in CAP LS';
  _write_client_line($bob, 'CAP REQ :overnet-e2ee');
  is _read_client_line($bob, 1_000), ':overnet.irc.local CAP * ACK :overnet-e2ee',
    'bob CAP REQ overnet-e2ee is acknowledged';
  _write_client_line($bob, 'CAP END');
  is _read_client_line_optional($bob, 200), undef, 'bob CAP END produces no extra line';
  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes the second E2EE DM subscription open';
  _write_client_line($bob, 'OVERNETKEY SET ' . $bob_key->pubkey_hex);
  is _read_client_line($bob, 1_000),
    ':overnet.irc.local NOTICE bob :OVERNETKEY SET ' . $bob_key->pubkey_hex,
    'bob registers his E2EE pubkey';

  _write_client_line($alice, 'OVERNETKEY GET bob');
  is _read_client_line($alice, 1_000),
    ':overnet.irc.local NOTICE alice :OVERNETKEY GET bob ' . $bob_key->pubkey_hex,
    'alice can query bob\'s E2EE pubkey';

  my $payload = {
    overnet_v    => '0.1.0',
    private_type => 'chat.dm_message',
    object_type  => 'chat.dm',
    object_id    => $bob_dm_object_id,
    provenance   => {
      type              => 'adapted',
      protocol          => 'irc',
      origin            => $network . '/bob',
      external_identity => 'alice',
      limitations       => ['unsigned'],
    },
    body => {
      text => 'secret hello',
    },
  };
  my $rumor = Net::Nostr::DirectMessage->create(
    sender_pubkey => $alice_key->pubkey_hex,
    content       => encode_json($payload),
    recipients    => [$bob_key->pubkey_hex],
  );
  my ($wrap) = Net::Nostr::DirectMessage->wrap_for_recipients(
    rumor       => $rumor,
    sender_key  => $alice_key,
    skip_sender => 1,
  );
  my $e2ee_body = '+overnet-e2ee-v1 ' . encode_base64(encode_json($wrap->to_hash), '');

  _write_client_line($alice, 'PRIVMSG bob :' . $e2ee_body);
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'private_message',
        overnet_et  => 'chat.dm_message',
        overnet_ot  => 'chat.dm',
        overnet_oid => $bob_dm_object_id,
      );
    },
  ), 'opaque E2EE direct-message PRIVMSG is emitted as a private message';
  $host->pump(timeout_ms => 100);

  my $received_line = _read_client_line($bob, 1_000);
  like $received_line, qr/\A:alice PRIVMSG bob :\+overnet-e2ee-v1 /,
    'bob receives an opaque E2EE direct-message PRIVMSG body';
  is _read_client_line_optional($alice, 200), undef,
    'sender does not receive a synthetic E2EE DM echo';

  my $received_transport = _decode_e2ee_transport_from_line($received_line);
  is_deeply $received_transport, $wrap->to_hash,
    'recipient receives the same visible wrapped transport that alice sent';

  my $received_rumor = Net::Nostr::DirectMessage->receive(
    event         => Net::Nostr::Event->from_wire($received_transport),
    recipient_key => $bob_key,
  );
  is $received_rumor->kind, 14, 'bob can locally unwrap a kind 14 rumor';
  is_deeply decode_json($received_rumor->content), $payload,
    'bob can locally decrypt the original private-message payload';

  my $opaque_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'private_message',
    overnet_et  => 'chat.dm_message',
    overnet_ot  => 'chat.dm',
    overnet_oid => $bob_dm_object_id,
  );
  ok $opaque_item, 'runtime recorded the opaque E2EE private message';
  _assert_opaque_private_message_metadata(
    $opaque_item,
    label           => 'opaque E2EE direct-message PRIVMSG',
    private_type    => 'chat.dm_message',
    object_id       => $bob_dm_object_id,
    sender_identity => 'alice',
  );

  my $shutdown = $host->request_shutdown(reason => 'opaque E2EE direct message test complete');
  is $shutdown->{state}, 'shutdown_complete', 'E2EE direct-message server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'E2EE direct-message server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program accepts TLS clients using the baseline tls config shape' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $channel_object_id = 'irc:' . $privmsg->{input}{network} . ':' . $privmsg->{input}{target};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $tls_cert_path = File::Spec->catfile($tmpdir, 'irc-server-cert.pem');
  my $tls_key_path = File::Spec->catfile($tmpdir, 'irc-server-key.pem');

  my $event_key = Net::Nostr::Key->new;
  $event_key->save_privkey($key_path);

  my ($cert, $tls_key) = CERT_create(
    subject => {
      commonName => 'localhost',
    },
    subjectAltNames => [
      [ DNS => 'localhost' ],
      [ IP  => '127.0.0.1' ],
    ],
  );
  PEM_cert2file($cert, $tls_cert_path);
  PEM_key2file($tls_key, $tls_key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
      tls              => {
        enabled          => JSON::PP::true,
        cert_chain_file  => $tls_cert_path,
        private_key_file => $tls_key_path,
        min_version      => 'TLSv1.2',
      },
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for the TLS server program';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'TLS-enabled server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'TLS-enabled server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'TLS-enabled server exposes the bound listen port';

  my $client = _connect_irc_client_tls($ready_details->{listen_port});

  _write_client_line($client, 'NICK alice');
  _write_client_line($client, 'USER alice 0 * :Alice TLS');
  _assert_registration_prelude(
    client  => $client,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'TLS client registration completes its DM subscription open';

  _write_client_line($client, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TLS client join is emitted through the runtime';
  is_deeply [
    _read_client_lines($client, 3, 1_000)
  ], [
    ':alice JOIN #overnet',
    ':overnet.irc.local 353 alice = #overnet :alice',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
  ], 'TLS client receives join plus the minimal NAMES bootstrap';

  my $time_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($client, 'PRIVMSG #overnet :Hello from TLS!');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.message',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TLS client channel message is emitted through the runtime';
  is _read_client_line($client, 1_000), ':alice PRIVMSG #overnet :Hello from TLS!',
    'TLS client receives subscription-driven PRIVMSG render';

  my $message_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'event',
    overnet_et  => 'chat.message',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $message_item, 'runtime recorded the TLS client channel message';
  like $message_item->{data}{id}, qr/\A[0-9a-f]{64}\z/, 'TLS message is signed as a Nostr event';
  cmp_ok $message_item->{data}{created_at}, '>=', $time_window->{min}, 'TLS message created_at is recent';
  cmp_ok $message_item->{data}{created_at}, '<=', $time_window->{max}, 'TLS message created_at stays within the test window';

  is _request_count_matching(
    $host->transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'TLS server opens one shared channel subscription';

  my $shutdown = $host->request_shutdown(reason => 'tls test complete');
  is $shutdown->{state}, 'shutdown_complete', 'TLS server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'TLS server exits cleanly';

  close $client->{socket};
};

subtest 'IRC server program drops TLS handshakes on the plain listener without exiting' => sub {
  my $tmpdir = tempdir(CLEANUP => 1);
  my $signing_key_path = File::Spec->catfile($tmpdir, 'plain-tls-probe-signing-key.pem');
  Overnet::Core::Nostr->generate_key->save_privkey($signing_key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.test',
      network          => 'local',
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $signing_key_path,
      adapter_config   => {},
    },
  );

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.test',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for the plain listener TLS probe';

  my $host = Overnet::Program::Host->new(
    command     => ['/opt/perl-5.42/bin/perl', $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.close_session'       => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'plain listener reaches ready state before the TLS probe';
  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'plain listener publishes ready health details';

  my $tls_client;
  my $tls_ok = eval {
    $tls_client = _connect_irc_client_tls($ready_details->{listen_port});
    1;
  };
  my $tls_error = $@;
  ok $tls_client || !$tls_ok, 'TLS probe reaches the plain listener';

  my $survived = eval {
    for (1 .. 10) {
      $host->pump(timeout_ms => 100);
      last if $host->has_exited;
    }
    1;
  };
  ok $survived, 'host pumping stays non-fatal after the TLS probe';
  ok !$host->has_exited, 'plain listener stays running after the TLS probe';

  if ($tls_client) {
    close $tls_client->{socket};
  }

  if (!$host->has_exited && $survived) {
    my $client = _connect_irc_client($ready_details->{listen_port});
    _write_client_line($client, 'NICK alice');
    _write_client_line($client, 'USER alice 0 * :Alice');
    _assert_registration_prelude(
      client  => $client,
      nick    => 'alice',
      network => 'local',
    );

    _write_client_line($client, 'QUIT :done');
    close $client->{socket};
  } else {
    fail('plain listener still accepts a normal client after the TLS probe');
  }

  my $shutdown = $host->request_shutdown(reason => 'plain tls probe complete');
  is $shutdown->{state}, 'shutdown_complete', 'plain listener handles runtime shutdown after the TLS probe';
  is $shutdown->{exit_code}, 0, 'plain listener exits cleanly after the TLS probe';
};

subtest 'IRC server program uses authoritative hosted-channel state for moderated IRC behavior' => sub {
  my $network = 'irc.authority.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $server_name = 'overnet.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.mock',
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
        mock_authoritative_channels => {
          $channel => {
            moderated        => 1,
            topic_restricted => 1,
            members          => [
              {
                pubkey => $alice_pubkey,
                roles  => ['irc.operator'],
              },
              {
                pubkey => $bob_pubkey,
                roles  => [],
              },
            ],
          },
        },
      },
    },
  );

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_000,
    )->to_hash,
  );
  push @{$seed_events[0]{tags}}, [ 'mode', 'moderated' ], [ 'mode', 'topic-restricted' ];

  my $authority_stream = _authoritative_nip29_stream_name(
    network    => $network,
    group_host => $group_host,
    group_id   => $group_id,
  );
  for my $event (@seed_events) {
    my $append = $runtime->append_event(
      stream => $authority_stream,
      event  => $event,
    );
    ok defined $append->{offset}, 'runtime stores seeded authoritative mock NIP-29 event';
  }

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.mock',
    definition => {
      kind             => 'class',
      class            => 'Local::MockAuthoritativeIRCAdapter',
      constructor_args => {},
    },
  ), 'runtime can register the mock authoritative adapter';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.read',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.derive'              => {},
      'adapters.close_session'       => {},
      'events.read'                  => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'authoritative server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'authoritative server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes its DM subscription open';

  _write_client_line($alice, 'OVERNETAUTH CHALLENGE');
  my $alice_challenge_line = _read_client_line($alice, 1_000);
  like $alice_challenge_line, qr/\A:\Q$server_name\E NOTICE alice :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'alice receives an authoritative auth challenge';
  $alice_challenge_line =~ /([0-9a-f]{64})\z/;
  my $alice_challenge = $1;
  _write_client_line($alice, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $alice_key,
    challenge => $alice_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($alice, 1_000), ":$server_name NOTICE alice :OVERNETAUTH AUTH $alice_pubkey",
    'alice authenticates her authoritative pubkey';

  _write_client_line($bob, 'OVERNETAUTH CHALLENGE');
  my $bob_challenge_line = _read_client_line($bob, 1_000);
  like $bob_challenge_line, qr/\A:\Q$server_name\E NOTICE bob :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'bob receives an authoritative auth challenge';
  $bob_challenge_line =~ /([0-9a-f]{64})\z/;
  my $bob_challenge = $1;
  _write_client_line($bob, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $bob_key,
    challenge => $bob_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($bob, 1_000), ":$server_name NOTICE bob :OVERNETAUTH AUTH $bob_pubkey",
    'bob authenticates his authoritative pubkey';

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps alice join requests';
  is _read_client_line($alice, 1_000), ":alice JOIN $channel",
    'alice receives her JOIN echo';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'authoritative JOIN bootstrap prefixes the operator nick';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line';

  _write_client_line($bob, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps bob join requests';
  is _read_client_line($alice, 1_000), ":bob JOIN $channel",
    'alice sees bob join the authoritative channel';
  is _read_client_line($bob, 1_000), ":bob JOIN $channel",
    'bob receives his JOIN echo';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 353 bob = $channel :\@alice bob",
    'bob sees authoritative prefixes during JOIN bootstrap';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 366 bob $channel :End of /NAMES list.",
    'bob receives the end-of-names line';

  _write_client_line($bob, "MODE $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps MODE query requests';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 324 bob $channel +mnt",
    'authoritative MODE query reflects derived channel modes';

  _write_client_line($bob, "PRIVMSG $channel :blocked");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps moderated PRIVMSG checks';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 404 bob $channel :Cannot send to channel",
    'moderated authoritative channels reject unvoiced senders';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_speak_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'program derives authoritative speak permission through the adapter';

  _write_client_line($bob, "TOPIC $channel :blocked");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps topic privilege checks';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 482 bob $channel :You're not channel operator",
    'topic-restricted authoritative channels reject non-operators';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_topic_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'program derives authoritative topic permission through the adapter';

  _write_client_line($alice, "TOPIC $channel :Authoritative topic");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps TOPIC writes';
  is _read_client_line($alice, 1_000), ":alice TOPIC $channel :Authoritative topic",
    'authoritative TOPIC writes are broadcast to the actor';
  is _read_client_line($bob, 1_000), ":alice TOPIC $channel :Authoritative topic",
    'authoritative TOPIC writes are broadcast to other joined channel members';

  _write_client_line($bob, "TOPIC $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps TOPIC query requests';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 332 bob $channel :Authoritative topic",
    'authoritative TOPIC query returns the current authoritative topic';

  _write_client_line($alice, "MODE $channel +v bob");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps MODE writes';
  is _read_client_line($alice, 1_000), ":alice MODE $channel +v bob",
    'operator mode changes are broadcast to the actor';
  is _read_client_line($bob, 1_000), ":alice MODE $channel +v bob",
    'operator mode changes are broadcast to the target';

  _write_client_line($bob, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps NAMES derivation';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 353 bob = $channel :\@alice +bob",
    'authoritative NAMES output reflects derived role prefixes after MODE';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 366 bob $channel :End of /NAMES list.",
    'bob receives the end-of-names line after NAMES';

  _write_client_line($alice, "KICK $channel bob :bye");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps KICK writes';
  is _read_client_line($alice, 1_000), ":alice KICK $channel bob :bye",
    'authoritative KICK is broadcast to the operator';
  is _read_client_line($bob, 1_000), ":alice KICK $channel bob :bye",
    'authoritative KICK is broadcast to the target';

  _write_client_line($alice, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative host pumps post-KICK NAMES derivation';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'kicked members disappear from authoritative NAMES output';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line after KICK';

  my $derived_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      ($_[0]{operation} || '') eq 'authoritative_channel_view'
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $derived_request, 'program requests authoritative channel derivation through the adapter';

  my $mode_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'MODE')
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{mode} || '') eq '+v');
    },
  );
  ok $mode_request, 'program routes authoritative MODE writes through the adapter';
  is $mode_request->{input}{actor_pubkey}, $alice_pubkey, 'authoritative MODE writes include actor_pubkey';
  is $mode_request->{input}{target_pubkey}, $bob_pubkey, 'authoritative MODE writes include target_pubkey';
  is_deeply $mode_request->{input}{current_roles}, [], 'authoritative MODE writes include current target roles';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_mode_write_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{mode} || '') eq '+v');
    },
  ) >= 1, 'program derives authoritative mode-write permission through the adapter';

  my $topic_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'TOPIC')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $topic_request, 'program routes authoritative TOPIC through the adapter';
  is $topic_request->{input}{actor_pubkey}, $alice_pubkey, 'authoritative TOPIC includes actor_pubkey';
  is $topic_request->{input}{text}, 'Authoritative topic', 'authoritative TOPIC includes the new topic text';
  ok ref($topic_request->{input}{group_metadata}) eq 'HASH', 'authoritative TOPIC includes current group metadata';
  ok $topic_request->{input}{group_metadata}{moderated}, 'authoritative TOPIC preserves the moderated metadata flag';
  ok $topic_request->{input}{group_metadata}{topic_restricted}, 'authoritative TOPIC preserves the topic-restricted metadata flag';

  my $kick_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'KICK')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $kick_request, 'program routes authoritative KICK through the adapter';
  is $kick_request->{input}{actor_pubkey}, $alice_pubkey, 'authoritative KICK includes actor_pubkey';
  is $kick_request->{input}{target_pubkey}, $bob_pubkey, 'authoritative KICK includes target_pubkey';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_channel_action_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{action} || '') eq 'kick')
        && (($_[0]{input}{target_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'program derives authoritative kick permission through the adapter';

  my $shutdown = $host->request_shutdown(reason => 'authoritative test complete');
  is $shutdown->{state}, 'shutdown_complete', 'authoritative server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'authoritative server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program authenticates authoritative clients through SASL NOSTR' => sub {
  my $network = 'irc.authority.sasl.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $server_name = 'overnet.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-sasl-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.sasl.mock',
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
        mock_authoritative_channels => {
          $channel => {
            topic_restricted => 1,
            members          => [
              {
                pubkey => $alice_pubkey,
                roles  => ['irc.operator'],
              },
            ],
          },
        },
      },
    },
  );

  my $authority_stream = _authoritative_nip29_stream_name(
    network    => $network,
    group_host => $group_host,
    group_id   => $group_id,
  );
  my $append = $runtime->append_event(
    stream => $authority_stream,
    event  => Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_200,
    )->to_hash,
  );
  ok defined $append->{offset}, 'runtime stores seeded authoritative SASL mock NIP-29 event';

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.sasl.mock',
    definition => {
      kind             => 'class',
      class            => 'Local::MockAuthoritativeIRCAdapter',
      constructor_args => {},
    },
  ), 'runtime can register the mock authoritative adapter for SASL coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.read',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.derive'              => {},
      'adapters.close_session'       => {},
      'events.read'                  => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'authoritative SASL server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'authoritative SASL server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'CAP LS 302');
  like _read_client_line($alice, 1_000),
    qr/\A:\Q$server_name\E CAP \* LS :message-tags server-time overnet-e2ee account-tag account-notify sasl\z/,
    'authoritative SASL server advertises IRCv3 tag/time, account, and sasl capabilities';

  _write_client_line($alice, 'CAP REQ :sasl');
  is _read_client_line($alice, 1_000), ":$server_name CAP * ACK :sasl",
    'authoritative SASL server ACKs CAP REQ :sasl';

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  is _read_client_line_optional($alice, 200), undef,
    'registration is deferred while SASL capability negotiation remains active';

  _write_client_line($alice, 'AUTHENTICATE NOSTR');
  my $challenge_payload = _read_authenticate_payload($alice, 1_000);
  is_deeply(
    {
      map { $_ => $challenge_payload->{$_} }
        grep { exists $challenge_payload->{$_} }
        qw(challenge scope relay_url delegate_pubkey session_id expires_at grant_kind)
    },
    {
      challenge => $challenge_payload->{challenge},
      scope     => _authoritative_auth_scope(
        server_name => $server_name,
        network     => $network,
      ),
    },
    'non-relay authoritative SASL challenge exposes only the auth challenge and scope',
  );
  like $challenge_payload->{challenge}, qr/\A[0-9a-f]{64}\z/,
    'non-relay authoritative SASL challenge carries a random challenge token';

  my $sasl_response_payload = encode_base64(
    encode_json({
      auth_event => _build_authoritative_auth_event_hash(
        key       => $alice_key,
        challenge => $challenge_payload->{challenge},
        scope     => $challenge_payload->{scope},
      ),
    }),
    '',
  );
  _write_authenticate_payload($alice, $sasl_response_payload);
  is _read_client_line($alice, 1_000), ":$server_name 903 alice :SASL authentication successful",
    'authoritative SASL NOSTR binds the authenticated pubkey successfully';

  _write_client_line($alice, 'CAP END');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open after SASL success';

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative SASL host pumps alice join requests';
  is _read_client_line($alice, 1_000), ":alice JOIN $channel",
    'alice receives her JOIN echo after SASL authentication';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'authoritative SASL JOIN bootstrap prefixes the operator nick';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives end-of-names after SASL-authenticated JOIN';

  _write_client_line($alice, "TOPIC $channel :Topic via SASL");
  ok $host->pump(timeout_ms => 200) >= 0,
    'authoritative SASL host pumps TOPIC writes';
  is _read_client_line($alice, 1_000), ":alice TOPIC $channel :Topic via SASL",
    'SASL-authenticated authoritative TOPIC succeeds';

  my $topic_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'TOPIC')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $topic_request, 'program routes SASL-authenticated authoritative TOPIC through the adapter';
  is $topic_request->{input}{actor_pubkey}, $alice_pubkey,
    'SASL-authenticated authoritative TOPIC binds the actor pubkey';

  my $shutdown = $host->request_shutdown(reason => 'authoritative sasl test complete');
  is $shutdown->{state}, 'shutdown_complete', 'authoritative SASL server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'authoritative SASL server exits cleanly';

  close $alice->{socket};
};

subtest 'IRC server program uses the real IRC adapter for authoritative NIP-29 channel state' => sub {
  my $network = 'irc.authority.real.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $server_name = 'overnet.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;
  my $authority_stream = _authoritative_nip29_stream_name(
    network    => $network,
    group_host => $group_host,
    group_id   => $group_id,
  );

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-real-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.real',
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
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real authoritative IRC adapter';

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_010,
      closed     => 0,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_011,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_012,
      members    => [
        $alice_pubkey,
        $bob_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_013,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );
  push @{$seed_events[0]{tags}}, [ 'mode', 'moderated' ], [ 'mode', 'topic-restricted' ];

  for my $event (@seed_events) {
    my $append = $runtime->append_event(
      stream => $authority_stream,
      event  => $event,
    );
    ok defined $append->{offset}, 'runtime stores seeded authoritative NIP-29 event';
  }

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.append',
      'events.read',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.derive'              => {},
      'adapters.close_session'       => {},
      'events.append'                => {},
      'events.read'                  => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'real authoritative server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'real authoritative server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open on the real authoritative server';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes its DM subscription open on the real authoritative server';

  _write_client_line($alice, 'OVERNETAUTH CHALLENGE');
  my $alice_challenge_line = _read_client_line($alice, 1_000);
  like $alice_challenge_line, qr/\A:\Q$server_name\E NOTICE alice :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'alice receives a real authoritative auth challenge';
  $alice_challenge_line =~ /([0-9a-f]{64})\z/;
  my $alice_challenge = $1;
  _write_client_line($alice, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $alice_key,
    challenge => $alice_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($alice, 1_000), ":$server_name NOTICE alice :OVERNETAUTH AUTH $alice_pubkey",
    'alice authenticates her authoritative pubkey on the real authoritative server';

  _write_client_line($bob, 'OVERNETAUTH CHALLENGE');
  my $bob_challenge_line = _read_client_line($bob, 1_000);
  like $bob_challenge_line, qr/\A:\Q$server_name\E NOTICE bob :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'bob receives a real authoritative auth challenge';
  $bob_challenge_line =~ /([0-9a-f]{64})\z/;
  my $bob_challenge = $1;
  _write_client_line($bob, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $bob_key,
    challenge => $bob_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($bob, 1_000), ":$server_name NOTICE bob :OVERNETAUTH AUTH $bob_pubkey",
    'bob authenticates his authoritative pubkey on the real authoritative server';

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps alice join requests';
  is _read_client_line($alice, 1_000), ":alice JOIN $channel",
    'alice receives her JOIN echo on the real authoritative server';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'real authoritative JOIN bootstrap prefixes the operator nick from NIP-29 state';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line from the real authoritative server';

  _write_client_line($bob, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps bob join requests';
  is _read_client_line($alice, 1_000), ":bob JOIN $channel",
    'alice sees bob join the authoritative channel on the real adapter path';
  is _read_client_line($bob, 1_000), ":bob JOIN $channel",
    'bob receives his JOIN echo on the real adapter path';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 353 bob = $channel :\@alice bob",
    'bob sees authoritative prefixes during JOIN bootstrap on the real adapter path';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 366 bob $channel :End of /NAMES list.",
    'bob receives the end-of-names line on the real adapter path';

  _write_client_line($bob, "MODE $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps MODE query requests';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 324 bob $channel +mnt",
    'real authoritative MODE query reflects derived channel modes';

  _write_client_line($bob, "PRIVMSG $channel :blocked");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps moderated PRIVMSG checks';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 404 bob $channel :Cannot send to channel",
    'real authoritative moderated channels reject unvoiced senders';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_speak_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'real authoritative program derives speak permission through the adapter';

  _write_client_line($bob, "TOPIC $channel :blocked");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps topic privilege checks';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 482 bob $channel :You're not channel operator",
    'real authoritative topic-restricted channels reject non-operators';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_topic_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'real authoritative program derives topic permission through the adapter';

  _write_client_line($alice, "TOPIC $channel :Real authoritative topic");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps TOPIC writes';
  is _read_client_line($alice, 1_000), ":alice TOPIC $channel :Real authoritative topic",
    'real authoritative TOPIC writes are broadcast to the actor';
  is _read_client_line($bob, 1_000), ":alice TOPIC $channel :Real authoritative topic",
    'real authoritative TOPIC writes are broadcast to other joined members';

  _write_client_line($bob, "TOPIC $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps TOPIC query requests';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 332 bob $channel :Real authoritative topic",
    'real authoritative TOPIC query returns the current authoritative topic';

  _write_client_line($alice, "MODE $channel +v bob");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps MODE writes';
  is _read_client_line($alice, 1_000), ":alice MODE $channel +v bob",
    'real authoritative MODE writes are broadcast to the actor';
  is _read_client_line($bob, 1_000), ":alice MODE $channel +v bob",
    'real authoritative MODE writes are broadcast to the target';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_mode_write_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{mode} || '') eq '+v');
    },
  ) >= 1, 'real authoritative program derives mode-write permission through the adapter';

  _write_client_line($bob, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps NAMES derivation';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 353 bob = $channel :\@alice +bob",
    'real authoritative NAMES output reflects derived role prefixes after MODE';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 366 bob $channel :End of /NAMES list.",
    'bob receives the end-of-names line after a real authoritative NAMES query';

  _write_client_line($alice, "KICK $channel bob :bye");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps KICK writes';
  is _read_client_line($alice, 1_000), ":alice KICK $channel bob :bye",
    'real authoritative KICK is broadcast to the operator';
  is _read_client_line($bob, 1_000), ":alice KICK $channel bob :bye",
    'real authoritative KICK is broadcast to the target';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_channel_action_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{action} || '') eq 'kick')
        && (($_[0]{input}{target_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'real authoritative program derives kick permission through the adapter';

  _write_client_line($alice, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'real authoritative host pumps post-KICK NAMES derivation';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'real authoritative kicked members disappear from NAMES output';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line after real authoritative KICK';

  my $shutdown = $host->request_shutdown(reason => 'real authoritative test complete');
  is $shutdown->{state}, 'shutdown_complete', 'real authoritative server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'real authoritative server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program rejects non-member JOIN on a closed authoritative channel' => sub {
  my $network = 'irc.authority.closed.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $server_name = 'overnet.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;
  my $authority_stream = _authoritative_nip29_stream_name(
    network    => $network,
    group_host => $group_host,
    group_id   => $group_id,
  );

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-closed-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.closed',
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
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.closed',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real authoritative IRC adapter for closed-channel admission coverage';

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_020,
      closed     => 1,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_021,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_022,
      members    => [
        $alice_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_023,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );

  for my $event (@seed_events) {
    my $append = $runtime->append_event(
      stream => $authority_stream,
      event  => $event,
    );
    ok defined $append->{offset}, 'runtime stores seeded closed authoritative NIP-29 event';
  }

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.append',
      'events.read',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.derive'              => {},
      'adapters.close_session'       => {},
      'events.append'                => {},
      'events.read'                  => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'closed authoritative server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'closed authoritative server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open on the closed authoritative server';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes its DM subscription open on the closed authoritative server';

  _write_client_line($alice, 'OVERNETAUTH CHALLENGE');
  my $alice_challenge_line = _read_client_line($alice, 1_000);
  like $alice_challenge_line, qr/\A:\Q$server_name\E NOTICE alice :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'alice receives a closed authoritative auth challenge';
  $alice_challenge_line =~ /([0-9a-f]{64})\z/;
  my $alice_challenge = $1;
  _write_client_line($alice, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $alice_key,
    challenge => $alice_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($alice, 1_000), ":$server_name NOTICE alice :OVERNETAUTH AUTH $alice_pubkey",
    'alice authenticates her authoritative pubkey on the closed authoritative server';

  _write_client_line($bob, 'OVERNETAUTH CHALLENGE');
  my $bob_challenge_line = _read_client_line($bob, 1_000);
  like $bob_challenge_line, qr/\A:\Q$server_name\E NOTICE bob :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
    'bob receives a closed authoritative auth challenge';
  $bob_challenge_line =~ /([0-9a-f]{64})\z/;
  my $bob_challenge = $1;
  _write_client_line($bob, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
    key       => $bob_key,
    challenge => $bob_challenge,
    scope     => _authoritative_auth_scope(
      server_name => $server_name,
      network     => $network,
    ),
  ));
  is _read_client_line($bob, 1_000), ":$server_name NOTICE bob :OVERNETAUTH AUTH $bob_pubkey",
    'bob authenticates his authoritative pubkey on the closed authoritative server';

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'closed authoritative host pumps alice join requests';
  is _read_client_line($alice, 1_000), ":alice JOIN $channel",
    'alice receives her JOIN echo on the closed authoritative server';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'closed authoritative JOIN bootstrap prefixes the operator nick from NIP-29 state';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line on the closed authoritative server';

  my $join_count_before = _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );

  _write_client_line($bob, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'closed authoritative host pumps bob join rejection';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 473 bob $channel :Cannot join channel (+i)",
    'closed authoritative channels reject non-member JOIN attempts';

  my $join_count_after = _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  is $join_count_after, $join_count_before,
    'rejected authoritative JOIN does not emit a mapped JOIN through the adapter';

  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_join_admission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel);
    },
  ) >= 2, 'program derives authoritative JOIN admission through the adapter for allowed and rejected JOINs';

  _write_client_line($alice, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'closed authoritative host pumps post-rejection NAMES';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'rejected authoritative JOIN does not leak the non-member into NAMES';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line after the rejected JOIN';

  my $shutdown = $host->request_shutdown(reason => 'closed authoritative join rejection test complete');
  is $shutdown->{state}, 'shutdown_complete', 'closed authoritative server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'closed authoritative server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program admits an invited user to a closed authoritative channel' => sub {
  my $network = 'irc.authority.invite.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $server_name = 'overnet.irc.local';
  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $carol_key = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;
  my $carol_pubkey = $carol_key->pubkey_hex;
  my $authority_stream = _authoritative_nip29_stream_name(
    network    => $network,
    group_host => $group_host,
    group_id   => $group_id,
  );

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-invite-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.invite',
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
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.invite',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real authoritative IRC adapter for invite coverage';

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_030,
      closed     => 1,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_031,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_032,
      members    => [
        $alice_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_033,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );

  for my $event (@seed_events) {
    my $append = $runtime->append_event(
      stream => $authority_stream,
      event  => $event,
    );
    ok defined $append->{offset}, 'runtime stores seeded invite authoritative NIP-29 event';
  }

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'events.append',
      'events.read',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_private_message',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'        => {},
      'adapters.map_input'           => {},
      'adapters.derive'              => {},
      'adapters.close_session'       => {},
      'events.append'                => {},
      'events.read'                  => {},
      'subscriptions.open'           => {},
      'subscriptions.close'          => {},
      'overnet.emit_event'           => {},
      'overnet.emit_state'           => {},
      'overnet.emit_private_message' => {},
      'overnet.emit_capabilities'    => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'invite authoritative server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'invite authoritative server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});
  my $carol = _connect_irc_client($ready_details->{listen_port});

  my $register_client = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client  => $args{client},
      nick    => $args{nick},
      network => $network,
    );
  };

  my $authenticate_client = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$server_name\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $server_name,
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000), ":$server_name NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey";
  };

  $register_client->(
    client   => $alice,
    nick     => 'alice',
    realname => 'Alice Example',
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open on the invite authoritative server';

  $register_client->(
    client   => $bob,
    nick     => 'bob',
    realname => 'Bob Example',
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes its DM subscription open on the invite authoritative server';

  $register_client->(
    client   => $carol,
    nick     => 'carol',
    realname => 'Carol Example',
  );
  ok _wait_for_dm_subscription_count($host, 3),
    'carol registration completes its DM subscription open on the invite authoritative server';

  $authenticate_client->(
    client => $alice,
    nick   => 'alice',
    key    => $alice_key,
    pubkey => $alice_pubkey,
  );
  $authenticate_client->(
    client => $bob,
    nick   => 'bob',
    key    => $bob_key,
    pubkey => $bob_pubkey,
  );
  $authenticate_client->(
    client => $carol,
    nick   => 'carol',
    key    => $carol_key,
    pubkey => $carol_pubkey,
  );

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps alice join requests';
  is _read_client_line($alice, 1_000), ":alice JOIN $channel",
    'alice receives her JOIN echo on the invite authoritative server';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice",
    'invite authoritative JOIN bootstrap prefixes the operator nick from NIP-29 state';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line on the invite authoritative server';

  _write_client_line($bob, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps bob pre-invite join rejection';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 473 bob $channel :Cannot join channel (+i)",
    'closed authoritative channel rejects bob before invite';

  _write_client_line($alice, "INVITE bob $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps INVITE writes';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 341 alice bob $channel",
    'operator receives the INVITE confirmation numeric';
  is _read_client_line($bob, 1_000), ":alice INVITE bob :$channel",
    'target receives the INVITE line';

  my $invite_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'INVITE')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $invite_request, 'program routes authoritative INVITE through the adapter';
  is $invite_request->{input}{actor_pubkey}, $alice_pubkey, 'authoritative INVITE includes actor_pubkey';
  is $invite_request->{input}{target_pubkey}, $bob_pubkey, 'authoritative INVITE includes target_pubkey';
  like $invite_request->{input}{invite_code}, qr/\A[0-9a-f]{64}\z/,
    'authoritative INVITE generates a deterministic invite code';
  ok _request_count_matching(
    $host->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_channel_action_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{action} || '') eq 'invite')
        && (($_[0]{input}{target_pubkey} || '') eq $bob_pubkey);
    },
  ) >= 1, 'program derives authoritative invite permission through the adapter';

  _write_client_line($bob, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps bob invited join';
  is _read_client_line($alice, 1_000), ":bob JOIN $channel",
    'alice sees the invited user join the closed authoritative channel';
  is _read_client_line($bob, 1_000), ":bob JOIN $channel",
    'bob receives his JOIN echo after invite';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 353 bob = $channel :\@alice bob",
    'bob sees invited membership during JOIN bootstrap';
  is _read_client_line($bob, 1_000), ":overnet.irc.local 366 bob $channel :End of /NAMES list.",
    'bob receives the end-of-names line after invited JOIN';

  my $join_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel)
        && defined($_[0]{input}{invite_code});
    },
  );
  ok $join_request, 'invited authoritative JOIN is routed through the adapter';
  is $join_request->{input}{actor_pubkey}, $bob_pubkey, 'invited authoritative JOIN includes actor_pubkey';
  is $join_request->{input}{invite_code}, $invite_request->{input}{invite_code},
    'invited authoritative JOIN uses the stored invite code';

  _write_client_line($carol, "JOIN $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps carol uninvited join rejection';
  is _read_client_line($carol, 1_000), ":overnet.irc.local 473 carol $channel :Cannot join channel (+i)",
    'closed authoritative channel still rejects an uninvited authenticated client';

  _write_client_line($alice, "NAMES $channel");
  ok $host->pump(timeout_ms => 200) >= 0,
    'invite authoritative host pumps post-invite NAMES';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 353 alice = $channel :\@alice bob",
    'invited join updates authoritative NAMES output';
  is _read_client_line($alice, 1_000), ":overnet.irc.local 366 alice $channel :End of /NAMES list.",
    'alice receives the end-of-names line after invite-mediated join';

  my $shutdown = $host->request_shutdown(reason => 'closed authoritative invite test complete');
  is $shutdown->{state}, 'shutdown_complete', 'invite authoritative server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'invite authoritative server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
  close $carol->{socket};
};

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program establishes authoritative relay delegation through SASL NOSTR' => sub {
  my $network = 'irc.authority.sasl.relay.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 10_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name = 'overnet.irc.local';

  my $alice_key = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_300,
      closed     => 1,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_301,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_302,
      members    => [
        $alice_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_303,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );
  my $seed_key = Net::Nostr::Key->new;
  @seed_events = map {
    $seed_key->create_event(
      kind       => $_->{kind},
      created_at => $_->{created_at},
      content    => $_->{content},
      tags       => $_->{tags},
    )->to_hash
  } @seed_events;

  for my $event (@seed_events) {
    my $publish = _publish_nostr_event_to_relay(
      relay_url => $relay_url,
      event     => $event,
    );
    ok $publish->{accepted}, 'relay accepts seeded authoritative SASL relay state';
  }

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-authority-sasl-relay-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.authoritative.sasl.relay',
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
        url              => $relay_url,
        poll_interval_ms => 50,
      },
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.authoritative.sasl.relay',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real authoritative IRC adapter for SASL relay coverage';

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
  is $host->state, 'ready', 'authoritative SASL relay server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'authoritative SASL relay server publishes ready health details';

  my $alice = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'CAP LS 302');
  like _read_client_line($alice, 1_000),
    qr/\A:\Q$server_name\E CAP \* LS :message-tags server-time overnet-e2ee account-tag account-notify sasl\z/,
    'authoritative SASL relay server advertises IRCv3 tag/time, account, and sasl capabilities';

  _write_client_line($alice, 'CAP REQ :sasl');
  is _read_client_line($alice, 1_000), ":$server_name CAP * ACK :sasl",
    'authoritative SASL relay server ACKs CAP REQ :sasl';

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Relay');
  is _read_client_line_optional($alice, 200), undef,
    'relay-backed registration is deferred while SASL capability negotiation remains active';

  _write_client_line($alice, 'AUTHENTICATE NOSTR');
  my $challenge_payload = _read_authenticate_payload($alice, 1_000);
  like $challenge_payload->{challenge}, qr/\A[0-9a-f]{64}\z/,
    'relay-backed SASL challenge carries a random challenge token';
  is $challenge_payload->{scope}, _authoritative_auth_scope(
    server_name => $server_name,
    network     => $network,
  ), 'relay-backed SASL challenge carries the authoritative auth scope';
  is $challenge_payload->{relay_url}, $relay_url,
    'relay-backed SASL challenge carries the relay URL';
  is $challenge_payload->{grant_kind}, _authoritative_grant_kind(),
    'relay-backed SASL challenge carries the delegation grant kind';
  like $challenge_payload->{delegate_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'relay-backed SASL challenge carries a delegated signing pubkey';
  like $challenge_payload->{session_id}, qr/\A[0-9a-f]{64}\z/,
    'relay-backed SASL challenge carries a delegation session id';
  like $challenge_payload->{expires_at}, qr/\A\d+\z/,
    'relay-backed SASL challenge carries a delegation expiration';

  my $sasl_response_payload = encode_base64(
    encode_json({
      auth_event => _build_authoritative_auth_event_hash(
        key       => $alice_key,
        challenge => $challenge_payload->{challenge},
        scope     => $challenge_payload->{scope},
      ),
      delegate_event => _build_authoritative_delegate_event_hash(
        key             => $alice_key,
        relay_url       => $challenge_payload->{relay_url},
        scope           => $challenge_payload->{scope},
        delegate_pubkey => $challenge_payload->{delegate_pubkey},
        session_id      => $challenge_payload->{session_id},
        expires_at      => $challenge_payload->{expires_at},
        nick            => 'alice',
      ),
    }),
    '',
  );
  _write_authenticate_payload($alice, $sasl_response_payload);
  ok $host->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'authoritative SASL relay host pumps the SASL response and delegation publish';
  is _read_client_line($alice, 3_000), ":$server_name 903 alice :SASL authentication successful",
    'relay-backed SASL NOSTR binds the authenticated pubkey and delegation successfully';

  ok _pump_hosts_until(
    hosts      => [ $host ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $grant_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds   => [ _authoritative_grant_kind() ],
            authors => [$alice_pubkey],
            limit   => 20,
          },
        ],
      );
      return scalar(@{$grant_events || []}) ? 1 : 0;
    },
  ), 'relay-backed SASL publishes the delegation grant to the relay';

  _write_client_line($alice, 'CAP END');
  _assert_registration_prelude(
    client      => $alice,
    nick        => 'alice',
    network     => $network,
    server_name => $server_name,
    timeout_ms  => 3_000,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open after relay-backed SASL success';

  _write_client_line($alice, "JOIN $channel");
  ok $host->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'authoritative SASL relay host pumps alice join requests';
  my $relay_sasl_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host],
    client          => $alice,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $relay_sasl_join_bootstrap,
    'authoritative SASL relay JOIN emits the expected bootstrap';
  is_deeply $relay_sasl_join_bootstrap, [
    ":alice JOIN $channel",
    ":$server_name 353 alice = $channel :\@alice",
    ":$server_name 366 alice $channel :End of /NAMES list.",
  ], 'alice receives JOIN plus operator-prefixed NAMES bootstrap after relay-backed SASL auth';

  my $relay_sasl_join_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $relay_sasl_join_request,
    'member-authorized relay-backed JOIN re-establishes authoritative presence through the adapter';
  is $relay_sasl_join_request->{input}{actor_pubkey}, $alice_pubkey,
    'the relay-backed member JOIN binds the effective actor pubkey';
  ok !defined $relay_sasl_join_request->{input}{invite_code},
    'the relay-backed member JOIN does not consume an invite code when membership is already retained';

  _write_client_line($alice, "TOPIC $channel :Relay topic via SASL");
  ok $host->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'authoritative SASL relay host pumps TOPIC writes';
  ok _pump_hosts_until(
    hosts      => [ $host ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      return defined _last_request_matching(
        $host->transcript,
        'from_program',
        'adapters.map_input',
        sub {
          ref($_[0]{input}) eq 'HASH'
            && (($_[0]{input}{command} || '') eq 'TOPIC')
            && (($_[0]{input}{target} || '') eq $channel);
        },
      ) ? 1 : 0;
    },
  ), 'relay-backed SASL TOPIC produces an authoritative adapter mapping request';
  ok _pump_hosts_until(
    hosts      => [ $host ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($alice, 50);
      return defined($line) && $line eq ":alice TOPIC $channel :Relay topic via SASL" ? 1 : 0;
    },
  ), 'SASL-authenticated relay-backed TOPIC succeeds';

  my $topic_request = _last_request_matching(
    $host->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'TOPIC')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $topic_request, 'program routes SASL-authenticated relay-backed TOPIC through the adapter';
  like $topic_request->{input}{signing_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'SASL-authenticated relay-backed TOPIC includes a delegated signing pubkey';
  like $topic_request->{input}{authority_event_id}, qr/\A[0-9a-f]{64}\z/,
    'SASL-authenticated relay-backed TOPIC includes a delegation grant reference';
  like $topic_request->{input}{authority_sequence}, qr/\A[1-9]\d*\z/,
    'SASL-authenticated relay-backed TOPIC includes a session delegation sequence';

  my $shutdown = $host->request_shutdown(reason => 'authoritative sasl relay test complete');
  is $shutdown->{state}, 'shutdown_complete', 'authoritative SASL relay server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'authoritative SASL relay server exits cleanly';

  close $alice->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program relay-publishes authoritative NIP-29 writes across two instances' => sub {
  my $network = 'irc.authority.relay.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 5_000;
  my $fresh_reinvite_timeout_ms = 10_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name_a = 'overnet-a.irc.local';
  my $server_name_b = 'overnet-b.irc.local';

  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_040,
      closed     => 1,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_041,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_042,
      members    => [
        $alice_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_043,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );
  my $seed_key = Net::Nostr::Key->new;
  @seed_events = map {
    $seed_key->create_event(
      kind       => $_->{kind},
      created_at => $_->{created_at},
      content    => $_->{content},
      tags       => $_->{tags},
    )->to_hash
  } @seed_events;

  for my $event (@seed_events) {
    my $publish = _publish_nostr_event_to_relay(
      relay_url => $relay_url,
      event     => $event,
    );
    ok $publish->{accepted}, 'relay accepts seeded authoritative NIP-29 state';
  }

  my $build_runtime = sub {
    my (%args) = @_;
    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_path = File::Spec->catfile($tmpdir, $args{name} . '-irc-server-key.pem');
    my $key = Net::Nostr::Key->new;
    $key->save_privkey($key_path);

    my $runtime = Overnet::Program::Runtime->new(
      config => {
        adapter_id       => $args{adapter_id},
        network          => $network,
        listen_host      => '127.0.0.1',
        listen_port      => 0,
        server_name      => $args{server_name},
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
          url              => $relay_url,
          poll_interval_ms => 50,
        },
      },
    );
    ok $runtime->register_adapter_definition(
      adapter_id => $args{adapter_id},
      definition => {
        kind             => 'class',
        class            => 'Overnet::Adapter::IRC',
        lib_dirs         => [$irc_lib],
        constructor_args => {},
      },
    ), "$args{name} runtime can register the real authoritative IRC adapter";

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
        'adapters.open_session'        => {},
        'adapters.map_input'           => {},
        'adapters.derive'              => {},
        'adapters.close_session'       => {},
        'events.append'                => {},
        'events.read'                  => {},
        'nostr.publish_event'          => {},
        'nostr.query_events'           => {},
        'nostr.open_subscription'      => {},
        'nostr.read_subscription_snapshot' => {},
        'nostr.close_subscription'     => {},
        'subscriptions.open'           => {},
        'subscriptions.close'          => {},
        'overnet.emit_event'           => {},
        'overnet.emit_state'           => {},
        'overnet.emit_private_message' => {},
        'overnet.emit_capabilities'    => {},
      },
      startup_timeout_ms  => 1_000,
      shutdown_timeout_ms => 1_000,
    );

    $host->start;
    is $host->state, 'ready', "$args{name} relay-backed authoritative server reaches ready state";
    my $ready = _wait_for_ready_details($host);
    ok $ready, "$args{name} relay-backed authoritative server publishes ready health details";

    return ($runtime, $host, $ready);
  };

  my ($runtime_a, $host_a, $ready_a) = $build_runtime->(
    name        => 'instance-a',
    adapter_id  => 'irc.authoritative.relay.a',
    server_name => $server_name_a,
  );
  my ($runtime_b, $host_b, $ready_b) = $build_runtime->(
    name        => 'instance-b',
    adapter_id  => 'irc.authoritative.relay.b',
    server_name => $server_name_b,
  );

  my $alice_a = _connect_irc_client($ready_a->{listen_port});
  my $bob_a   = _connect_irc_client($ready_a->{listen_port});
  my $bob_b   = _connect_irc_client($ready_b->{listen_port});

  my $register = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client      => $args{client},
      nick        => $args{nick},
      network     => $network,
      server_name => $args{server_name},
      timeout_ms  => 3_000,
    );
  };

  my $authenticate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge on $args{name}";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey on $args{name}";
  };
  my $delegate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($args{client}, 3_000);
    like $delegate_line,
      qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      "$args{nick} receives session delegation parameters on $args{name}";
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $args{key},
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => $args{nick},
    ));
    ok $args{host}->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      "$args{nick} pumps the relay-backed delegation publish on $args{name}";
    is _read_client_line($args{client}, 3_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
      "$args{nick} establishes a session delegation grant on $args{name}";
  };

  $register->(
    client      => $alice_a,
    nick        => 'alice',
    realname    => 'Alice Relay',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 1),
    'instance A alice registration completes its DM subscription open';

  $register->(
    client      => $bob_a,
    nick        => 'bob',
    realname    => 'Bob Relay A',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 2),
    'instance A bob registration completes its DM subscription open';

  $register->(
    client      => $bob_b,
    nick        => 'bob',
    realname    => 'Bob Relay B',
    server_name => $server_name_b,
  );
  ok _wait_for_dm_subscription_count($host_b, 1),
    'instance B bob registration completes its DM subscription open';

  $authenticate->(
    name        => 'instance A',
    client      => $alice_a,
    nick        => 'alice',
    key         => $alice_key,
    pubkey      => $alice_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance A',
    client      => $bob_a,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance B',
    client      => $bob_b,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_b,
  );
  $delegate->(
    name        => 'instance A',
    client      => $alice_a,
    host        => $host_a,
    nick        => 'alice',
    key         => $alice_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance A',
    client      => $bob_a,
    host        => $host_a,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance B',
    client      => $bob_b,
    host        => $host_b,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_b,
  );

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps alice relay-backed join request';
  my $instance_a_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host_a],
    client          => $alice_a,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $instance_a_join_bootstrap,
    'instance A emits the initial relay-backed JOIN bootstrap';
  is_deeply $instance_a_join_bootstrap, [
    ":alice JOIN $channel",
    ":$server_name_a 353 alice = $channel :\@alice",
    ":$server_name_a 366 alice $channel :End of /NAMES list.",
  ], 'alice receives JOIN plus operator bootstrap on instance A';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob pre-invite join request';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":$server_name_b 473 bob $channel :Cannot join channel (+i)" ? 1 : 0;
    },
  ), 'instance B rejects bob before the relay-backed invite';

  _write_client_line($alice_a, "TOPIC $channel :Relay-backed topic");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps relay-backed TOPIC write';
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":alice TOPIC $channel :Relay-backed topic" ? 1 : 0;
    },
  ), 'alice sees the relay-backed TOPIC line on instance A';
  my $relay_topic_request = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'TOPIC')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $relay_topic_request, 'instance A routes the relay-backed TOPIC through the adapter';
  is $relay_topic_request->{input}{actor_pubkey}, $alice_pubkey,
    'instance A relay-backed TOPIC includes actor_pubkey';
  is $relay_topic_request->{input}{text}, 'Relay-backed topic',
    'instance A relay-backed TOPIC includes the new topic text';
  like $relay_topic_request->{input}{signing_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'instance A relay-backed TOPIC includes a delegated signing pubkey';
  like $relay_topic_request->{input}{authority_event_id}, qr/\A[0-9a-f]{64}\z/,
    'instance A relay-backed TOPIC includes a delegation grant reference';
  like $relay_topic_request->{input}{authority_sequence}, qr/\A[1-9]\d*\z/,
    'instance A relay-backed TOPIC includes a session-scoped delegation sequence';
  ok(
    _pump_hosts_until(
      hosts      => [ $host_a, $host_b ],
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms => $relay_propagation_timeout_ms,
      condition  => sub {
        my $relay_topics = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [9002],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        return scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{topic}) && $tags{topic} eq 'Relay-backed topic'
            && defined($tags{overnet_actor}) && $tags{overnet_actor} eq $alice_pubkey
            && defined($tags{overnet_authority}) && $tags{overnet_authority} =~ /\A[0-9a-f]{64}\z/
            && defined($tags{overnet_sequence}) && $tags{overnet_sequence} =~ /\A[1-9]\d*\z/
        } @{$relay_topics}) ? 1 : 0;
      },
    ),
    'the relay exposes the delegated authoritative TOPIC event',
  );

  _write_client_line($alice_a, "INVITE bob $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps relay-backed INVITE write';
  my $local_invite_numeric = _read_client_line_optional($alice_a, 3_000);
  ok !defined($local_invite_numeric) || $local_invite_numeric eq ":$server_name_a 341 alice bob $channel",
    'instance A either emits or suppresses the local INVITE confirmation numeric consistently';
  my $local_invite_line = _read_client_line_optional($bob_a, 3_000);
  ok !defined($local_invite_line) || $local_invite_line eq ":alice INVITE bob :$channel",
    'instance A either emits or suppresses the local same-instance INVITE line consistently';
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      return defined _last_request_matching(
        $host_a->transcript,
        'from_program',
        'adapters.map_input',
        sub {
          ref($_[0]{input}) eq 'HASH'
            && (($_[0]{input}{command} || '') eq 'INVITE')
            && (($_[0]{input}{target} || '') eq $channel);
        },
      ) ? 1 : 0;
    },
  ), 'instance A records the relay-backed INVITE mapping request';
  my $relay_invite_request = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'INVITE')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $relay_invite_request, 'instance A routes the relay-backed INVITE through the adapter';
  is $relay_invite_request->{input}{actor_pubkey}, $alice_pubkey,
    'instance A relay-backed INVITE includes actor_pubkey';
  is $relay_invite_request->{input}{target_pubkey}, $bob_pubkey,
    'instance A relay-backed INVITE includes target_pubkey';
  like $relay_invite_request->{input}{signing_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'instance A relay-backed INVITE includes a delegated signing pubkey';
  like $relay_invite_request->{input}{authority_event_id}, qr/\A[0-9a-f]{64}\z/,
    'instance A relay-backed INVITE includes a delegation grant reference';
  like $relay_invite_request->{input}{authority_sequence}, qr/\A[1-9]\d*\z/,
    'instance A relay-backed INVITE includes a session-scoped delegation sequence';
  ok(
    _pump_hosts_until(
      hosts      => [ $host_a, $host_b ],
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms => $relay_propagation_timeout_ms,
      condition  => sub {
        my $relay_invites = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [9009],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        return scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{p}) && $tags{p} eq $bob_pubkey
        } @{$relay_invites}) ? 1 : 0;
      },
    ),
    'the relay exposes the delegated authoritative INVITE event',
  );

  my $bob_b_saw_invite = _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":alice INVITE bob :$channel" ? 1 : 0;
    },
  );

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob relay-backed invited join';
  my $relay_join_request = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  if (!$relay_join_request) {
    _write_client_line($bob_b, "JOIN $channel");
    ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      'instance B pumps bob relay-backed join retry after invite propagation';
    $relay_join_request = _last_request_matching(
      $host_b->transcript,
      'from_program',
      'adapters.map_input',
      sub {
        ref($_[0]{input}) eq 'HASH'
          && (($_[0]{input}{command} || '') eq 'JOIN')
          && (($_[0]{input}{target} || '') eq $channel);
      },
    );
  }
  ok $relay_join_request, 'instance B routes the relay-backed JOIN through the adapter when invite admission is available';
  like $relay_join_request->{input}{signing_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'instance B relay-backed JOIN includes a delegated signing pubkey';
  like $relay_join_request->{input}{authority_event_id}, qr/\A[0-9a-f]{64}\z/,
    'instance B relay-backed JOIN includes a delegation grant reference';
  like $relay_join_request->{input}{authority_sequence}, qr/\A[1-9]\d*\z/,
    'instance B relay-backed JOIN includes a session-scoped delegation sequence';
  ok(
    _pump_hosts_until(
      hosts      => [ $host_a, $host_b ],
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms => $relay_propagation_timeout_ms,
      condition  => sub {
        my $relay_joins = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [9021],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        return scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{overnet_actor}) && $tags{overnet_actor} eq $bob_pubkey
        } @{$relay_joins}) ? 1 : 0;
      },
    ),
    'the relay exposes the delegated authoritative JOIN event',
  );
  my @bob_b_post_join_lines;
  my $bob_b_join_echo = _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return 0 unless defined $line;
      push @bob_b_post_join_lines, $line;
      $bob_b_saw_invite = 1 if $line eq ":alice INVITE bob :$channel";
      return $line eq ":bob JOIN $channel" ? 1 : 0;
    },
  );
  ok $bob_b_join_echo,
    'bob receives his relay-backed JOIN echo on instance B'
      or diag(
        'instance B post-join lines: '
          . (@bob_b_post_join_lines ? join(' | ', @bob_b_post_join_lines) : '(none)'),
        'instance B last subscriptions.open request: '
          . encode_json(
              _last_request_matching(
                $host_b->transcript,
                'from_program',
                'subscriptions.open',
              ) || {}
            ),
        'instance B last nostr.publish_event request: '
          . encode_json(
              _last_request_matching(
                $host_b->transcript,
                'from_program',
                'nostr.publish_event',
              ) || {}
            ),
      );
  like _read_client_line($bob_b, 3_000),
    qr/\A:(?:alice|\Q$server_name_b\E) TOPIC \Q$channel\E :Relay-backed topic\z/,
    'instance B join bootstrap replays the propagated authoritative topic';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 353 bob = $channel :\@alice bob",
    'instance B NAMES bootstrap reflects authoritative remote presence after the relay-backed join';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 366 bob $channel :End of /NAMES list.",
    'instance B bob receives end-of-names after the relay-backed join';

  _write_client_line($bob_b, "TOPIC $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps propagated authoritative TOPIC query';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 332 bob $channel :Relay-backed topic",
    'instance B authoritative TOPIC query returns the propagated topic';

  _write_client_line($bob_b, "PART $channel :later");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob relay-backed PART';
  my $relay_part_request = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'PART')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  ok $relay_part_request, 'instance B routes the relay-backed PART through the adapter';
  like $relay_part_request->{input}{signing_pubkey}, qr/\A[0-9a-f]{64}\z/,
    'instance B relay-backed PART includes a delegated signing pubkey';
  like $relay_part_request->{input}{authority_event_id}, qr/\A[0-9a-f]{64}\z/,
    'instance B relay-backed PART includes a delegation grant reference';
  like $relay_part_request->{input}{authority_sequence}, qr/\A[1-9]\d*\z/,
    'instance B relay-backed PART includes a session-scoped delegation sequence';
  is _read_client_line($bob_b, 3_000), ":bob PART $channel :later",
    'bob receives his relay-backed PART echo on instance B';
  my $relay_parts = _query_nostr_events_from_relay(
    relay_url => $relay_url,
    filters   => [
      {
        kinds => [9022],
        '#h'  => [$group_id],
        limit => 20,
      },
    ],
  );
  ok(
    scalar(grep {
      my %tags = _first_tag_values($_->{tags});
      defined($tags{overnet_actor}) && $tags{overnet_actor} eq $bob_pubkey
        && defined($tags{overnet_authority}) && $tags{overnet_authority} =~ /\A[0-9a-f]{64}\z/
        && defined($tags{overnet_sequence}) && $tags{overnet_sequence} =~ /\A[1-9]\d*\z/
    } @{$relay_parts}),
    'the relay exposes the delegated authoritative PART event',
  );
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps relay-backed PART propagation before the fresh INVITE';
  my @alice_a_post_part_lines;
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return 0 unless defined $line;
      push @alice_a_post_part_lines, $line;
      return $line eq ":bob PART $channel :later" ? 1 : 0;
    },
  ), 'instance A alice receives the propagated relay-backed PART'
    or diag(
      'instance A post-PART lines: '
        . (@alice_a_post_part_lines ? join(' | ', @alice_a_post_part_lines) : '(none)'),
    );

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob post-PART rejoin attempt';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 473 bob $channel :Cannot join channel (+i)",
    'instance B requires a fresh invite after relay-backed PART on a closed channel';

  my $relay_invites_before_reinvite = _query_nostr_events_from_relay(
    relay_url => $relay_url,
    filters   => [
      {
        kinds => [9009],
        '#h'  => [$group_id],
        limit => 20,
      },
    ],
  );
  my %relay_invite_ids_before_reinvite = map {
    defined($_->{id}) && !ref($_->{id}) ? ($_->{id} => 1) : ()
  } @{$relay_invites_before_reinvite || []};
  my $invite_request_count_before_reinvite = _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'INVITE')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  my $invite_publish_count_before_reinvite = _request_count_matching(
    $host_a->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 9009);
    },
  );

  _write_client_line($alice_a, "INVITE bob $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps a fresh relay-backed INVITE after PART';
  my $fresh_local_invite_numeric;
  my $fresh_same_instance_invite;
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $fresh_reinvite_timeout_ms,
    condition  => sub {
      $fresh_local_invite_numeric ||= _read_client_line_optional($alice_a, 50);
      $fresh_same_instance_invite ||= _read_client_line_optional($bob_a, 50);
      my $invite_request_count_after_reinvite = _request_count_matching(
        $host_a->transcript,
        'from_program',
        'adapters.map_input',
        sub {
          ref($_[0]{input}) eq 'HASH'
            && (($_[0]{input}{command} || '') eq 'INVITE')
            && (($_[0]{input}{target} || '') eq $channel);
        },
      );
      my $invite_publish_count_after_reinvite = _request_count_matching(
        $host_a->transcript,
        'from_program',
        'nostr.publish_event',
        sub {
          ref($_[0]{event}) eq 'HASH'
            && (($_[0]{event}{kind} || 0) == 9009);
        },
      );
      return 1 if defined($fresh_local_invite_numeric) || defined($fresh_same_instance_invite);
      return $invite_request_count_after_reinvite > $invite_request_count_before_reinvite
        && $invite_publish_count_after_reinvite > $invite_publish_count_before_reinvite
        ? 1 : 0;
    },
  ), 'instance A routes and publishes a fresh relay-backed INVITE after PART';
  $fresh_local_invite_numeric ||= _read_client_line_optional($alice_a, 50);
  $fresh_same_instance_invite ||= _read_client_line_optional($bob_a, 50);
  ok(
    _pump_hosts_until(
      hosts      => [ $host_a, $host_b ],
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms => $fresh_reinvite_timeout_ms,
      condition  => sub {
        my $relay_invites = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          timeout_ms => 1_000,
          filters   => [
            {
              kinds => [9009],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        return scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{p}) && $tags{p} eq $bob_pubkey
            && defined($_->{id}) && !ref($_->{id})
            && !$relay_invite_ids_before_reinvite{$_->{id}}
        } @{$relay_invites}) ? 1 : 0;
      },
    ),
    'the relay exposes a fresh authoritative INVITE event after PART',
  ) or diag(
    'instance A local fresh-invite line: ' . (($fresh_local_invite_numeric // '(none)')),
    'instance A same-instance fresh invite line: ' . (($fresh_same_instance_invite // '(none)')),
    'instance A fresh INVITE request count: ' . $invite_request_count_before_reinvite . ' -> '
      . _request_count_matching(
          $host_a->transcript,
          'from_program',
          'adapters.map_input',
          sub {
            ref($_[0]{input}) eq 'HASH'
              && (($_[0]{input}{command} || '') eq 'INVITE')
              && (($_[0]{input}{target} || '') eq $channel);
          },
        ),
    'instance A fresh INVITE publish count: ' . $invite_publish_count_before_reinvite . ' -> '
      . _request_count_matching(
          $host_a->transcript,
          'from_program',
          'nostr.publish_event',
          sub {
            ref($_[0]{event}) eq 'HASH'
              && (($_[0]{event}{kind} || 0) == 9009);
          },
        ),
    'instance A last authoritative derive request: '
      . encode_json(
          _last_request_matching(
            $host_a->transcript,
            'from_program',
            'adapters.derive',
          ) || {}
        ),
    'instance A last subscription snapshot request: '
      . encode_json(
          _last_request_matching(
            $host_a->transcript,
            'from_program',
            'nostr.read_subscription_snapshot',
          ) || {}
        ),
    'instance A last fresh INVITE map_input request: '
      . encode_json(
          _last_request_matching(
            $host_a->transcript,
            'from_program',
            'adapters.map_input',
            sub {
              ref($_[0]{input}) eq 'HASH'
                && (($_[0]{input}{command} || '') eq 'INVITE')
                && (($_[0]{input}{target} || '') eq $channel);
            },
          ) || {}
        ),
    'instance A last nostr.publish_event request: '
      . encode_json(
          _last_request_matching(
            $host_a->transcript,
            'from_program',
            'nostr.publish_event',
          ) || {}
        ),
  );
  $fresh_local_invite_numeric ||= _read_client_line_optional($alice_a, 500);
  my $bob_b_saw_fresh_invite = _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $fresh_reinvite_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":alice INVITE bob :$channel" ? 1 : 0;
    },
  );

  my $join_request_count_before_reinvite = _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob rejoin after the fresh relay-backed INVITE';
  my $join_request_count_after_reinvite = _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  if ($join_request_count_after_reinvite == $join_request_count_before_reinvite) {
    _write_client_line($bob_b, "JOIN $channel");
    ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      'instance B pumps bob rejoin retry after the fresh invite propagation';
    $join_request_count_after_reinvite = _request_count_matching(
      $host_b->transcript,
      'from_program',
      'adapters.map_input',
      sub {
        ref($_[0]{input}) eq 'HASH'
          && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel);
      },
    );
  }
  ok $join_request_count_after_reinvite > $join_request_count_before_reinvite,
    'instance B routes a fresh invited rejoin through the adapter after PART';
  my @bob_b_reinvite_lines;
  my $bob_b_reinvite_join_echo = _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $fresh_reinvite_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return 0 unless defined $line;
      push @bob_b_reinvite_lines, $line;
      $bob_b_saw_fresh_invite = 1 if $line eq ":alice INVITE bob :$channel";
      return $line eq ":bob JOIN $channel" ? 1 : 0;
    },
  );
  ok $bob_b_reinvite_join_echo,
    'bob receives his JOIN echo after the fresh relay-backed INVITE'
      or diag(
        'instance B fresh-invite lines: '
          . (@bob_b_reinvite_lines ? join(' | ', @bob_b_reinvite_lines) : '(none)'),
      );
  ok !defined($fresh_local_invite_numeric) || $fresh_local_invite_numeric eq ":$server_name_a 341 alice bob $channel",
    'instance A either emits or suppresses the fresh local INVITE confirmation numeric consistently';
  like _read_client_line($bob_b, 3_000),
    qr/\A:(?:alice|\Q$server_name_b\E) TOPIC \Q$channel\E :Relay-backed topic\z/,
    'instance B join bootstrap replays the propagated authoritative topic after the fresh invite';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 353 bob = $channel :\@alice bob",
    'instance B NAMES bootstrap restores bob and retained remote presence after the fresh relay-backed INVITE';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 366 bob $channel :End of /NAMES list.",
    'instance B bob receives end-of-names after rejoining through a fresh invite';

  my $mode_request_count_before = _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'MODE')
        && (($_[0]{input}{target} || '') eq $channel);
    },
  );
  my $mode_publish_count_before = _request_count_matching(
    $host_a->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 9000);
    },
  );
  _write_client_line($alice_a, "MODE $channel +v bob");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps relay-backed MODE write';
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $mode_request_count_after = _request_count_matching(
        $host_a->transcript,
        'from_program',
        'adapters.map_input',
        sub {
          ref($_[0]{input}) eq 'HASH'
            && (($_[0]{input}{command} || '') eq 'MODE')
            && (($_[0]{input}{target} || '') eq $channel);
        },
      );
      my $mode_publish_count_after = _request_count_matching(
        $host_a->transcript,
        'from_program',
        'nostr.publish_event',
        sub {
          ref($_[0]{event}) eq 'HASH'
            && (($_[0]{event}{kind} || 0) == 9000);
        },
      );
      return $mode_request_count_after > $mode_request_count_before
        && $mode_publish_count_after > $mode_publish_count_before
        ? 1 : 0;
    },
  ), 'instance A routes and publishes the relay-backed MODE write';
  my @alice_a_mode_lines;
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      push @alice_a_mode_lines, $line if defined $line;
      return defined($line) && $line eq ":alice MODE $channel +v bob" ? 1 : 0;
    },
  ), 'alice sees the relay-backed MODE line on instance A'
    or diag(
      'instance A post-MODE lines: '
        . (@alice_a_mode_lines ? join(' | ', @alice_a_mode_lines) : '(none)'),
    );

  _write_client_line($bob_b, "NAMES $channel");
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":$server_name_b 353 bob = $channel :\@alice +bob" ? 1 : 0;
    },
  ), 'instance B authoritative NAMES reflects bob voice alongside retained remote presence after the relay-backed MODE';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 366 bob $channel :End of /NAMES list.",
    'instance B authoritative NAMES terminates after the propagated MODE';

  _write_client_line($alice_a, "KICK $channel bob :relay kick");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps relay-backed KICK write';
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":alice KICK $channel bob :relay kick" ? 1 : 0;
    },
  ), 'alice sees the relay-backed KICK line on instance A';
  my $relay_kicks = _query_nostr_events_from_relay(
    relay_url => $relay_url,
    filters   => [
      {
        kinds => [9001],
        '#h'  => [$group_id],
        limit => 20,
      },
    ],
  );
  ok(
    scalar(grep {
      my %tags = _first_tag_values($_->{tags});
      defined($tags{p}) && $tags{p} eq $bob_pubkey
        && defined($tags{overnet_actor}) && $tags{overnet_actor} eq $alice_pubkey
        && defined($tags{overnet_authority}) && $tags{overnet_authority} =~ /\A[0-9a-f]{64}\z/
        && defined($tags{overnet_sequence}) && $tags{overnet_sequence} =~ /\A[1-9]\d*\z/
    } @{$relay_kicks}),
    'the relay exposes the delegated authoritative KICK event',
  );

  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line =~ /\A:[^ ]+ KICK \Q$channel\E bob(?: :relay kick)?\z/ ? 1 : 0;
    },
  ), 'instance B bob receives the propagated relay-backed KICK';

  _write_client_line($bob_b, "NAMES $channel");
  ok _pump_hosts_until(
    hosts      => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms => $relay_propagation_timeout_ms,
    condition  => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":$server_name_b 353 bob = $channel :\@alice" ? 1 : 0;
    },
  ), 'instance B authoritative NAMES removes bob after the relay-backed KICK while retaining remote operator presence';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 366 bob $channel :End of /NAMES list.",
    'instance B authoritative NAMES terminates after the relay-backed KICK';

  my $shutdown_a = $host_a->request_shutdown(reason => 'relay-backed authoritative test complete A');
  is $shutdown_a->{state}, 'shutdown_complete', 'instance A relay-backed authoritative server handles runtime shutdown';
  is $shutdown_a->{exit_code}, 0, 'instance A relay-backed authoritative server exits cleanly';

  my $shutdown_b = $host_b->request_shutdown(reason => 'relay-backed authoritative test complete B');
  is $shutdown_b->{state}, 'shutdown_complete', 'instance B relay-backed authoritative server handles runtime shutdown';
  is $shutdown_b->{exit_code}, 0, 'instance B relay-backed authoritative server exits cleanly';

  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'nostr.open_subscription',
    sub { (($_[0]{relay_url} || '') eq $relay_url) ? 1 : 0 },
  ) >= 1, 'instance A opens a runtime nostr subscription for authoritative relay state';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'nostr.open_subscription',
    sub { (($_[0]{relay_url} || '') eq $relay_url) ? 1 : 0 },
  ) >= 1, 'instance B opens a runtime nostr subscription for authoritative relay state';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'nostr.read_subscription_snapshot',
    sub { 1 },
  ) >= 1, 'instance A reads runtime nostr subscription snapshots';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'nostr.read_subscription_snapshot',
    sub { 1 },
  ) >= 1, 'instance B reads runtime nostr subscription snapshots';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 14142 || ($_[0]{event}{kind} || 0) == 9009 || ($_[0]{event}{kind} || 0) == 9002 || ($_[0]{event}{kind} || 0) == 9001);
    },
  ) >= 1, 'instance A publishes authoritative relay events through the runtime nostr service';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 14142 || ($_[0]{event}{kind} || 0) == 9021 || ($_[0]{event}{kind} || 0) == 9022);
    },
  ) >= 1, 'instance B publishes authoritative relay events through the runtime nostr service';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub { (($_[0]{operation} || '') eq 'authoritative_join_admission') ? 1 : 0 },
  ) >= 1, 'instance A derives authoritative relay JOIN admission through the adapter';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.derive',
    sub { (($_[0]{operation} || '') eq 'authoritative_join_admission') ? 1 : 0 },
  ) >= 1, 'instance B derives authoritative relay JOIN admission through the adapter';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub { (($_[0]{operation} || '') eq 'authoritative_channel_view') ? 1 : 0 },
  ) >= 1, 'instance A derives authoritative relay state through authoritative_channel_view';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.derive',
    sub { (($_[0]{operation} || '') eq 'authoritative_channel_view') ? 1 : 0 },
  ) >= 1, 'instance B derives authoritative relay state through authoritative_channel_view';

  close $alice_a->{socket};
  close $bob_a->{socket};
  close $bob_b->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program creates and discovers authoritative hosted channels across two instances' => sub {
  my $network = 'irc.authority.create.test';
  my $channel = '#Fresh';
  my $group_host = 'groups.example.test';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 5_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name_a = 'overnet-create-a.irc.local';
  my $server_name_b = 'overnet-create-b.irc.local';

  my $canonical_channel = $channel;
  $canonical_channel =~ tr/A-Z[]\\^/a-z{}|~/;
  my $group_id = join(
    '-',
    'irc',
    unpack('H*', $network),
    unpack('H*', $canonical_channel),
  );

  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $build_runtime = sub {
    my (%args) = @_;
    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_path = File::Spec->catfile($tmpdir, $args{name} . '-irc-server-key.pem');
    my $key = Net::Nostr::Key->new;
    $key->save_privkey($key_path);

    my $runtime = Overnet::Program::Runtime->new(
      config => {
        adapter_id       => $args{adapter_id},
        network          => $network,
        listen_host      => '127.0.0.1',
        listen_port      => 0,
        server_name      => $args{server_name},
        signing_key_file => $key_path,
        adapter_config   => {
          network           => $network,
          authority_profile => 'nip29',
          group_host        => $group_host,
        },
        authority_relay => {
          url              => $relay_url,
          poll_interval_ms => 50,
        },
      },
    );
    ok $runtime->register_adapter_definition(
      adapter_id => $args{adapter_id},
      definition => {
        kind             => 'class',
        class            => 'Overnet::Adapter::IRC',
        lib_dirs         => [$irc_lib],
        constructor_args => {},
      },
    ), "$args{name} runtime can register the real authoritative IRC adapter";

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
        'adapters.open_session'        => {},
        'adapters.map_input'           => {},
        'adapters.derive'              => {},
        'adapters.close_session'       => {},
        'events.append'                => {},
        'events.read'                  => {},
        'nostr.publish_event'          => {},
        'nostr.query_events'           => {},
        'nostr.open_subscription'      => {},
        'nostr.read_subscription_snapshot' => {},
        'nostr.close_subscription'     => {},
        'subscriptions.open'           => {},
        'subscriptions.close'          => {},
        'overnet.emit_event'           => {},
        'overnet.emit_state'           => {},
        'overnet.emit_private_message' => {},
        'overnet.emit_capabilities'    => {},
      },
      startup_timeout_ms  => 1_000,
      shutdown_timeout_ms => 1_000,
    );

    $host->start;
    is $host->state, 'ready', "$args{name} created-channel server reaches ready state";
    my $ready = _wait_for_ready_details($host);
    ok $ready, "$args{name} created-channel server publishes ready health details";

    return ($runtime, $host, $ready);
  };

  my ($runtime_a, $host_a, $ready_a) = $build_runtime->(
    name        => 'create-instance-a',
    adapter_id  => 'irc.authoritative.create.a',
    server_name => $server_name_a,
  );
  my ($runtime_b, $host_b, $ready_b) = $build_runtime->(
    name        => 'create-instance-b',
    adapter_id  => 'irc.authoritative.create.b',
    server_name => $server_name_b,
  );

  my $alice_a = _connect_irc_client($ready_a->{listen_port});
  my $bob_b   = _connect_irc_client($ready_b->{listen_port});

  my $register = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client      => $args{client},
      nick        => $args{nick},
      network     => $network,
      server_name => $args{server_name},
      timeout_ms  => 3_000,
    );
  };

  my $authenticate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge on $args{name}";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey on $args{name}";
  };

  my $delegate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($args{client}, 3_000);
    like $delegate_line,
      qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      "$args{nick} receives session delegation parameters on $args{name}";
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $args{key},
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => $args{nick},
    ));
    ok $args{host}->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      "$args{nick} pumps the created-channel delegation publish on $args{name}";
    is _read_client_line($args{client}, 3_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
      "$args{nick} establishes a session delegation grant on $args{name}";
  };

  $register->(
    client      => $alice_a,
    nick        => 'alice',
    realname    => 'Alice Create',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 1),
    'instance A alice registration completes its DM subscription open';

  $register->(
    client      => $bob_b,
    nick        => 'bob',
    realname    => 'Bob Create',
    server_name => $server_name_b,
  );
  ok _wait_for_dm_subscription_count($host_b, 1),
    'instance B bob registration completes its DM subscription open';

  $authenticate->(
    name        => 'instance A',
    client      => $alice_a,
    nick        => 'alice',
    key         => $alice_key,
    pubkey      => $alice_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance B',
    client      => $bob_b,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_b,
  );
  $delegate->(
    name        => 'instance A',
    client      => $alice_a,
    host        => $host_a,
    nick        => 'alice',
    key         => $alice_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance B',
    client      => $bob_b,
    host        => $host_b,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_b,
  );

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps hosted-channel creation JOIN';
  my $alice_creation_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host_a],
    client          => $alice_a,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $alice_creation_bootstrap,
    'instance A emits the hosted-channel creation bootstrap';
  is_deeply $alice_creation_bootstrap, [
    ":alice JOIN $channel",
    ":$server_name_a 353 alice = $channel :\@alice",
    ":$server_name_a 366 alice $channel :End of /NAMES list.",
  ], 'alice receives JOIN plus operator-seeded NAMES bootstrap for the created hosted channel';

  ok(
    _pump_hosts_until(
      hosts           => [ $host_a, $host_b ],
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
      condition       => sub {
        my $metadata_events = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [39000],
              '#d'  => [$group_id],
              limit => 20,
            },
          ],
        );
        my $role_events = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [9000],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        my $join_events = _query_nostr_events_from_relay(
          relay_url => $relay_url,
          filters   => [
            {
              kinds => [9021],
              '#h'  => [$group_id],
              limit => 20,
            },
          ],
        );
        my $has_metadata = scalar(@{$metadata_events}) ? 1 : 0;
        my $has_operator = scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{p}) && $tags{p} eq $alice_pubkey
            && defined($tags{overnet_actor}) && $tags{overnet_actor} eq $alice_pubkey
        } @{$role_events}) ? 1 : 0;
        my $has_join = scalar(grep {
          my %tags = _first_tag_values($_->{tags});
          defined($tags{overnet_actor}) && $tags{overnet_actor} eq $alice_pubkey
        } @{$join_events}) ? 1 : 0;
        return $has_metadata && $has_operator && $has_join ? 1 : 0;
      },
    ),
    'the relay exposes metadata, operator bootstrap, and join events for the created hosted channel',
  );

  _write_client_line($bob_b, "LIST $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps LIST against the created hosted channel';
  my $discovered_list_lines = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $discovered_list_lines,
    'instance B emits the LIST response for the discovered hosted channel';
  is $discovered_list_lines->[0], ":$server_name_b 321 bob Channel :Users Name",
    'instance B LIST starts normally for discovered hosted channels';
  like $discovered_list_lines->[1],
    qr/\A:\Q$server_name_b\E 322 bob \Q$channel\E 1 :\z/,
    'instance B LIST discovers the created hosted channel before bob joins';
  is $discovered_list_lines->[2], ":$server_name_b 323 bob :End of /LIST",
    'instance B LIST ends normally for discovered hosted channels';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_list_entry_view')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel);
    },
  ) >= 1, 'instance B derives authoritative LIST rendering through the adapter';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob join against the discovered hosted channel';
  my $discovered_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $discovered_join_bootstrap,
    'instance B emits the join bootstrap for the discovered hosted channel';
  is_deeply $discovered_join_bootstrap, [
    ":bob JOIN $channel",
    ":$server_name_b 353 bob = $channel :\@alice bob",
    ":$server_name_b 366 bob $channel :End of /NAMES list.",
  ], 'bob receives JOIN plus discovered remote operator state on the hosted channel';
  my $discovered_join_request = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'JOIN')
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey)
        && !$_[0]{input}{create_channel};
    },
  );
  ok $discovered_join_request,
    'instance B routes the discovered hosted-channel JOIN through the adapter';
  my $discovered_join_publish = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 9021);
    },
  );
  ok $discovered_join_publish,
    'instance B publishes the discovered hosted-channel JOIN to the relay';
  my %discovered_join_publish_tags = _first_tag_values($discovered_join_publish->{event}{tags});
  is $discovered_join_publish_tags{h}, $group_id,
    'the discovered hosted-channel JOIN publish targets the expected group id';
  is $discovered_join_publish_tags{overnet_actor}, $bob_pubkey,
    'the discovered hosted-channel JOIN publish carries bob as the effective actor';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $join_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [9021],
            '#h'  => [$group_id],
            limit => 20,
          },
        ],
      );
      return scalar(grep {
        my %tags = _first_tag_values($_->{tags});
        defined($tags{overnet_actor}) && $tags{overnet_actor} eq $bob_pubkey;
      } @{$join_events}) ? 1 : 0;
    },
  ), 'the relay exposes bob membership for the discovered hosted-channel JOIN';

  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":bob JOIN $channel" ? 1 : 0;
    },
  ), 'instance A receives the propagated join from the second instance';

  _write_client_line($alice_a, "PART $channel :done");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps alice part from the created hosted channel';
  is _read_client_line($alice_a, 3_000), ":alice PART $channel :done",
    'alice receives her PART echo on the created hosted channel';
  my $propagated_alice_part = _pump_hosts_until_client_lines(
    hosts           => [ $host_a, $host_b ],
    client          => $bob_b,
    count           => 1,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $propagated_alice_part,
    'instance B receives the propagated PART from the first instance';
  is_deeply $propagated_alice_part, [
    ":alice PART $channel :done",
  ], 'bob receives the propagated alice PART on the created hosted channel';

  _write_client_line($bob_b, "PART $channel :done");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps bob part from the created hosted channel';
  my $bob_part_request = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'PART')
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $bob_pubkey);
    },
  );
  ok $bob_part_request,
    'instance B routes the discovered hosted-channel PART through the adapter';
  my $bob_part_publish = _last_request_matching(
    $host_b->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      ref($_[0]{event}) eq 'HASH'
        && (($_[0]{event}{kind} || 0) == 9022);
    },
  );
  ok $bob_part_publish,
    'instance B publishes the discovered hosted-channel PART to the relay';
  my %bob_part_publish_tags = _first_tag_values($bob_part_publish->{event}{tags});
  is $bob_part_publish_tags{h}, $group_id,
    'the discovered hosted-channel PART publish targets the expected group id';
  is $bob_part_publish_tags{overnet_actor}, $bob_pubkey,
    'the discovered hosted-channel PART publish carries bob as the effective actor';
  is _read_client_line($bob_b, 3_000), ":bob PART $channel :done",
    'bob receives his PART echo on the created hosted channel';

  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $relay_parts = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [9022],
            '#h'  => [$group_id],
            limit => 20,
          },
        ],
      );
      my %actors = map {
        my %tags = _first_tag_values($_->{tags});
        defined($tags{overnet_actor}) ? ($tags{overnet_actor} => 1) : ()
      } @{$relay_parts};
      return $actors{$alice_pubkey} && $actors{$bob_pubkey} ? 1 : 0;
    },
  ), 'the relay exposes PART events for both members of the created hosted channel';

  _write_client_line($bob_b, "LIST $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps LIST after the created hosted channel empties';
  my $empty_list_lines = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $empty_list_lines,
    'instance B emits the LIST response after the created hosted channel empties';
  is $empty_list_lines->[0], ":$server_name_b 321 bob Channel :Users Name",
    'instance B LIST still starts after the created hosted channel empties';
  like $empty_list_lines->[1],
    qr/\A:\Q$server_name_b\E 322 bob \Q$channel\E 0 :\z/,
    'instance B LIST still exposes the empty created hosted channel';
  is $empty_list_lines->[2], ":$server_name_b 323 bob :End of /LIST",
    'instance B LIST still ends after the created hosted channel empties';

  my $shutdown_a = $host_a->request_shutdown(reason => 'created hosted channel test complete');
  is $shutdown_a->{state}, 'shutdown_complete', 'instance A created-channel server handles runtime shutdown';
  is $shutdown_a->{exit_code}, 0, 'instance A created-channel server exits cleanly';
  my $shutdown_b = $host_b->request_shutdown(reason => 'created hosted channel test complete');
  is $shutdown_b->{state}, 'shutdown_complete', 'instance B created-channel server handles runtime shutdown';
  is $shutdown_b->{exit_code}, 0, 'instance B created-channel server exits cleanly';

  close $alice_a->{socket};
  close $bob_b->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program tombstones authoritative hosted channels across two instances' => sub {
  my $network = 'irc.authority.delete.test';
  my $channel = '#Gone';
  my $group_host = 'groups.example.test';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 5_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name_a = 'overnet-delete-a.irc.local';
  my $server_name_b = 'overnet-delete-b.irc.local';
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => $network,
    channel => $channel,
  );

  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $build_runtime = sub {
    my (%args) = @_;
    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_path = File::Spec->catfile($tmpdir, $args{name} . '-irc-server-key.pem');
    my $key = Net::Nostr::Key->new;
    $key->save_privkey($key_path);

    my $runtime = Overnet::Program::Runtime->new(
      config => {
        adapter_id       => $args{adapter_id},
        network          => $network,
        listen_host      => '127.0.0.1',
        listen_port      => 0,
        server_name      => $args{server_name},
        signing_key_file => $key_path,
        adapter_config   => {
          network           => $network,
          authority_profile => 'nip29',
          group_host        => $group_host,
        },
        authority_relay => {
          url              => $relay_url,
          poll_interval_ms => 50,
        },
      },
    );
    ok $runtime->register_adapter_definition(
      adapter_id => $args{adapter_id},
      definition => {
        kind             => 'class',
        class            => 'Overnet::Adapter::IRC',
        lib_dirs         => [$irc_lib],
        constructor_args => {},
      },
    ), "$args{name} runtime can register the real authoritative IRC adapter";

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
        'adapters.open_session'        => {},
        'adapters.map_input'           => {},
        'adapters.derive'              => {},
        'adapters.close_session'       => {},
        'events.append'                => {},
        'events.read'                  => {},
        'nostr.publish_event'          => {},
        'nostr.query_events'           => {},
        'nostr.open_subscription'      => {},
        'nostr.read_subscription_snapshot' => {},
        'nostr.close_subscription'     => {},
        'subscriptions.open'           => {},
        'subscriptions.close'          => {},
        'overnet.emit_event'           => {},
        'overnet.emit_state'           => {},
        'overnet.emit_private_message' => {},
        'overnet.emit_capabilities'    => {},
      },
      startup_timeout_ms  => 1_000,
      shutdown_timeout_ms => 1_000,
    );

    $host->start;
    is $host->state, 'ready', "$args{name} tombstone server reaches ready state";
    my $ready = _wait_for_ready_details($host);
    ok $ready, "$args{name} tombstone server publishes ready health details";

    return ($runtime, $host, $ready);
  };

  my ($runtime_a, $host_a, $ready_a) = $build_runtime->(
    name        => 'delete-instance-a',
    adapter_id  => 'irc.authoritative.delete.a',
    server_name => $server_name_a,
  );
  my ($runtime_b, $host_b, $ready_b) = $build_runtime->(
    name        => 'delete-instance-b',
    adapter_id  => 'irc.authoritative.delete.b',
    server_name => $server_name_b,
  );

  my $alice_a = _connect_irc_client($ready_a->{listen_port});
  my $bob_b   = _connect_irc_client($ready_b->{listen_port});

  my $register = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client      => $args{client},
      nick        => $args{nick},
      network     => $network,
      server_name => $args{server_name},
      timeout_ms  => 3_000,
    );
  };

  my $authenticate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge on $args{name}";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey on $args{name}";
  };

  my $delegate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($args{client}, 3_000);
    like $delegate_line,
      qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      "$args{nick} receives session delegation parameters on $args{name}";
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $args{key},
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => $args{nick},
    ));
    ok $args{host}->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      "$args{nick} pumps the tombstone delegation publish on $args{name}";
    is _read_client_line($args{client}, 3_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
      "$args{nick} establishes a session delegation grant on $args{name}";
  };

  my $drain_client_lines = sub {
    my ($client, $max_lines) = @_;
    my @lines;
    for (1 .. ($max_lines || 10)) {
      my $line = _read_client_line_optional($client, 100);
      last unless defined $line;
      push @lines, $line;
    }
    return \@lines;
  };

  $register->(
    client      => $alice_a,
    nick        => 'alice',
    realname    => 'Alice Delete',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 1),
    'instance A alice registration completes its DM subscription open for tombstoning';

  $register->(
    client      => $bob_b,
    nick        => 'bob',
    realname    => 'Bob Delete',
    server_name => $server_name_b,
  );
  ok _wait_for_dm_subscription_count($host_b, 1),
    'instance B bob registration completes its DM subscription open for tombstoning';

  $authenticate->(
    name        => 'instance A',
    client      => $alice_a,
    nick        => 'alice',
    key         => $alice_key,
    pubkey      => $alice_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance B',
    client      => $bob_b,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_b,
  );
  $delegate->(
    name        => 'instance A',
    client      => $alice_a,
    host        => $host_a,
    nick        => 'alice',
    key         => $alice_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance B',
    client      => $bob_b,
    host        => $host_b,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_b,
  );

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps authoritative hosted-channel creation before tombstoning';
  is_deeply(
    _pump_hosts_until_client_lines(
      hosts           => [$host_a],
      client          => $alice_a,
      count           => 3,
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
    ),
    [
      ":alice JOIN $channel",
      ":$server_name_a 353 alice = $channel :\@alice",
      ":$server_name_a 366 alice $channel :End of /NAMES list.",
    ],
    'alice receives the authoritative hosted-channel creation bootstrap before tombstoning',
  );

  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $metadata_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [39000],
            '#d'  => [$group_id],
            limit => 20,
          },
        ],
      );
      return scalar(@{$metadata_events}) ? 1 : 0;
    },
  ), 'the relay exposes authoritative metadata before tombstoning';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps authoritative JOIN before tombstoning';
  is_deeply(
    _pump_hosts_until_client_lines(
      hosts           => [$host_b],
      client          => $bob_b,
      count           => 3,
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
    ),
    [
      ":bob JOIN $channel",
      ":$server_name_b 353 bob = $channel :\@alice bob",
      ":$server_name_b 366 bob $channel :End of /NAMES list.",
    ],
    'bob joins the authoritative hosted channel before tombstoning',
  );

  _write_client_line($alice_a, "OVERNETCHANNEL DELETE $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps the authoritative hosted-channel delete request';

  my $delete_request = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'DELETE')
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey);
    },
  );
  ok $delete_request,
    'instance A routes the authoritative hosted-channel delete through the adapter';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_channel_action_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{action} || '') eq 'delete');
    },
  ) >= 1, 'instance A derives authoritative delete permission through the adapter';

  my $delete_publish = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      return 0 unless ref($_[0]{event}) eq 'HASH';
      return 0 unless (($_[0]{event}{kind} || 0) == 9002);
      return scalar grep {
        ref($_) eq 'ARRAY'
          && @{$_} >= 2
          && (($_->[0] || '') eq 'status')
          && (($_->[1] || '') eq 'tombstoned')
      } @{$_[0]{event}{tags} || []};
    },
  );
  ok $delete_publish,
    'instance A publishes a tombstoning metadata edit to the relay';

  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $metadata_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [9002],
            '#h'  => [$group_id],
            limit => 20,
          },
        ],
      );
      return scalar(grep {
        scalar grep {
          ref($_) eq 'ARRAY'
            && @{$_} >= 2
            && (($_->[0] || '') eq 'status')
            && (($_->[1] || '') eq 'tombstoned')
        } @{$_->{tags} || []}
      } @{$metadata_events}) ? 1 : 0;
    },
  ), 'the relay exposes the authoritative hosted-channel tombstone';

  $drain_client_lines->($alice_a, 10);
  $drain_client_lines->($bob_b, 10);

  _write_client_line($bob_b, "LIST $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps LIST after the hosted channel is tombstoned';
  my $tombstoned_list_lines = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 2,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $tombstoned_list_lines,
    'instance B emits a LIST response after the hosted channel is tombstoned';
  is_deeply $tombstoned_list_lines, [
    ":$server_name_b 321 bob Channel :Users Name",
    ":$server_name_b 323 bob :End of /LIST",
  ], 'instance B LIST omits the tombstoned hosted channel';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps JOIN against the tombstoned hosted channel';
  is _read_client_line($bob_b, 3_000),
    ":$server_name_b 403 bob $channel :No such channel",
    'instance B rejects JOIN against the tombstoned hosted channel';

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps JOIN against the tombstoned hosted channel';
  is _read_client_line($alice_a, 3_000),
    ":$server_name_a 403 alice $channel :No such channel",
    'instance A does not implicitly recreate the tombstoned hosted channel';

  my $shutdown_a = $host_a->request_shutdown(reason => 'tombstoned hosted channel test complete');
  is $shutdown_a->{state}, 'shutdown_complete', 'instance A tombstone server handles runtime shutdown';
  is $shutdown_a->{exit_code}, 0, 'instance A tombstone server exits cleanly';
  my $shutdown_b = $host_b->request_shutdown(reason => 'tombstoned hosted channel test complete');
  is $shutdown_b->{state}, 'shutdown_complete', 'instance B tombstone server handles runtime shutdown';
  is $shutdown_b->{exit_code}, 0, 'instance B tombstone server exits cleanly';

  close $alice_a->{socket};
  close $bob_b->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program reactivates tombstoned authoritative hosted channels across two instances' => sub {
  my $network = 'irc.authority.undelete.test';
  my $channel = '#Return';
  my $group_host = 'groups.example.test';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 5_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name_a = 'overnet-undelete-a.irc.local';
  my $server_name_b = 'overnet-undelete-b.irc.local';
  my $topic_text = 'Retained topic';
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => $network,
    channel => $channel,
  );

  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $build_runtime = sub {
    my (%args) = @_;
    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_path = File::Spec->catfile($tmpdir, $args{name} . '-irc-server-key.pem');
    my $key = Net::Nostr::Key->new;
    $key->save_privkey($key_path);

    my $runtime = Overnet::Program::Runtime->new(
      config => {
        adapter_id       => $args{adapter_id},
        network          => $network,
        listen_host      => '127.0.0.1',
        listen_port      => 0,
        server_name      => $args{server_name},
        signing_key_file => $key_path,
        adapter_config   => {
          network           => $network,
          authority_profile => 'nip29',
          group_host        => $group_host,
        },
        authority_relay => {
          url              => $relay_url,
          poll_interval_ms => 50,
        },
      },
    );
    ok $runtime->register_adapter_definition(
      adapter_id => $args{adapter_id},
      definition => {
        kind             => 'class',
        class            => 'Overnet::Adapter::IRC',
        lib_dirs         => [$irc_lib],
        constructor_args => {},
      },
    ), "$args{name} runtime can register the real authoritative IRC adapter";

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
        'adapters.open_session'        => {},
        'adapters.map_input'           => {},
        'adapters.derive'              => {},
        'adapters.close_session'       => {},
        'events.append'                => {},
        'events.read'                  => {},
        'nostr.publish_event'          => {},
        'nostr.query_events'           => {},
        'nostr.open_subscription'      => {},
        'nostr.read_subscription_snapshot' => {},
        'nostr.close_subscription'     => {},
        'subscriptions.open'           => {},
        'subscriptions.close'          => {},
        'overnet.emit_event'           => {},
        'overnet.emit_state'           => {},
        'overnet.emit_private_message' => {},
        'overnet.emit_capabilities'    => {},
      },
      startup_timeout_ms  => 1_000,
      shutdown_timeout_ms => 1_000,
    );

    $host->start;
    is $host->state, 'ready', "$args{name} undelete server reaches ready state";
    my $ready = _wait_for_ready_details($host);
    ok $ready, "$args{name} undelete server publishes ready health details";

    return ($runtime, $host, $ready);
  };

  my ($runtime_a, $host_a, $ready_a) = $build_runtime->(
    name        => 'undelete-instance-a',
    adapter_id  => 'irc.authoritative.undelete.a',
    server_name => $server_name_a,
  );
  my ($runtime_b, $host_b, $ready_b) = $build_runtime->(
    name        => 'undelete-instance-b',
    adapter_id  => 'irc.authoritative.undelete.b',
    server_name => $server_name_b,
  );

  my $alice_a = _connect_irc_client($ready_a->{listen_port});
  my $bob_b   = _connect_irc_client($ready_b->{listen_port});

  my $register = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client      => $args{client},
      nick        => $args{nick},
      network     => $network,
      server_name => $args{server_name},
      timeout_ms  => 3_000,
    );
  };

  my $authenticate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge on $args{name}";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey on $args{name}";
  };

  my $delegate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($args{client}, 3_000);
    like $delegate_line,
      qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      "$args{nick} receives session delegation parameters on $args{name}";
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $args{key},
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => $args{nick},
    ));
    ok $args{host}->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      "$args{nick} pumps the undelete delegation publish on $args{name}";
    is _read_client_line($args{client}, 3_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
      "$args{nick} establishes a session delegation grant on $args{name}";
  };

  my $drain_client_lines = sub {
    my ($client, $max_lines) = @_;
    my @lines;
    for (1 .. ($max_lines || 10)) {
      my $line = _read_client_line_optional($client, 100);
      last unless defined $line;
      push @lines, $line;
    }
    return \@lines;
  };

  $register->(
    client      => $alice_a,
    nick        => 'alice',
    realname    => 'Alice Undelete',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 1),
    'instance A alice registration completes its DM subscription open for undelete coverage';

  $register->(
    client      => $bob_b,
    nick        => 'bob',
    realname    => 'Bob Undelete',
    server_name => $server_name_b,
  );
  ok _wait_for_dm_subscription_count($host_b, 1),
    'instance B bob registration completes its DM subscription open for undelete coverage';

  $authenticate->(
    name        => 'instance A',
    client      => $alice_a,
    nick        => 'alice',
    key         => $alice_key,
    pubkey      => $alice_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance B',
    client      => $bob_b,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_b,
  );
  $delegate->(
    name        => 'instance A',
    client      => $alice_a,
    host        => $host_a,
    nick        => 'alice',
    key         => $alice_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance B',
    client      => $bob_b,
    host        => $host_b,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_b,
  );

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps authoritative hosted-channel creation before undelete';
  is_deeply(
    _pump_hosts_until_client_lines(
      hosts           => [$host_a],
      client          => $alice_a,
      count           => 3,
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
    ),
    [
      ":alice JOIN $channel",
      ":$server_name_a 353 alice = $channel :\@alice",
      ":$server_name_a 366 alice $channel :End of /NAMES list.",
    ],
    'alice receives the authoritative hosted-channel creation bootstrap before undelete',
  );

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps authoritative JOIN before undelete';
  is_deeply(
    _pump_hosts_until_client_lines(
      hosts           => [$host_b],
      client          => $bob_b,
      count           => 3,
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
    ),
    [
      ":bob JOIN $channel",
      ":$server_name_b 353 bob = $channel :\@alice bob",
      ":$server_name_b 366 bob $channel :End of /NAMES list.",
    ],
    'bob joins the authoritative hosted channel before undelete',
  );
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":bob JOIN $channel" ? 1 : 0;
    },
  ), 'alice sees the retained member join before the channel is tombstoned';

  _write_client_line($alice_a, "TOPIC $channel :$topic_text");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps retained authoritative TOPIC before undelete';
  my $topic_lines = _pump_hosts_until_client_lines(
    hosts           => [ $host_a, $host_b ],
    client          => $alice_a,
    count           => 1,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $topic_lines,
    'alice receives the authoritative TOPIC line before undelete';
  is_deeply $topic_lines, [
    ":alice TOPIC $channel :$topic_text",
  ], 'the authoritative TOPIC line is rendered before undelete';
  $drain_client_lines->($bob_b, 10);

  _write_client_line($alice_a, "MODE $channel +i");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps retained authoritative MODE +i before undelete';
  my $mode_lines = _pump_hosts_until_client_lines(
    hosts           => [ $host_a, $host_b ],
    client          => $alice_a,
    count           => 1,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $mode_lines,
    'alice receives the authoritative MODE +i line before undelete';
  is_deeply $mode_lines, [
    ":alice MODE $channel +i",
  ], 'the authoritative MODE +i line is rendered before undelete';
  $drain_client_lines->($bob_b, 10);

  _write_client_line($alice_a, "OVERNETCHANNEL DELETE $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps the tombstone request before undelete';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $metadata_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [9002],
            '#h'  => [$group_id],
            limit => 20,
          },
        ],
      );
      return scalar(grep {
        scalar grep {
          ref($_) eq 'ARRAY'
            && @{$_} >= 2
            && (($_->[0] || '') eq 'status')
            && (($_->[1] || '') eq 'tombstoned')
        } @{$_->{tags} || []}
      } @{$metadata_events}) ? 1 : 0;
    },
  ), 'the relay exposes the tombstone before UNDELETE';
  $drain_client_lines->($alice_a, 10);
  $drain_client_lines->($bob_b, 10);

  _write_client_line($alice_a, "OVERNETCHANNEL UNDELETE $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps the authoritative hosted-channel undelete request';

  my $undelete_request = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'adapters.map_input',
    sub {
      ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{command} || '') eq 'UNDELETE')
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey);
    },
  );
  ok $undelete_request,
    'instance A routes the authoritative hosted-channel UNDELETE through the adapter';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_channel_action_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{action} || '') eq 'undelete');
    },
  ) >= 1, 'instance A derives authoritative undelete permission through the adapter';

  my $undelete_publish = _last_request_matching(
    $host_a->transcript,
    'from_program',
    'nostr.publish_event',
    sub {
      return 0 unless ref($_[0]{event}) eq 'HASH';
      return 0 unless (($_[0]{event}{kind} || 0) == 9002);
      my @tags = @{$_[0]{event}{tags} || []};
      return 0 if grep {
        ref($_) eq 'ARRAY'
          && @{$_} >= 2
          && (($_->[0] || '') eq 'status')
          && (($_->[1] || '') eq 'tombstoned')
      } @tags;
      return scalar grep {
        ref($_) eq 'ARRAY'
          && @{$_} >= 2
          && (($_->[0] || '') eq 'topic')
          && (($_->[1] || '') eq $topic_text)
      } @tags;
    },
  );
  ok $undelete_publish,
    'instance A publishes an undelete metadata edit that retains the prior topic';

  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $metadata_events = _query_nostr_events_from_relay(
        relay_url => $relay_url,
        filters   => [
          {
            kinds => [9002],
            '#h'  => [$group_id],
            limit => 20,
          },
        ],
      );
      return 0 unless @{$metadata_events} >= 4;
      my @sorted = sort {
        (($a->{created_at} || 0) <=> ($b->{created_at} || 0))
      } @{$metadata_events};
      my $latest = $sorted[-1];
      return 0 unless ref($latest) eq 'HASH';
      return 0 if grep {
        ref($_) eq 'ARRAY'
          && @{$_} >= 2
          && (($_->[0] || '') eq 'status')
          && (($_->[1] || '') eq 'tombstoned')
      } @{ $latest->{tags} || [] };
      return scalar grep {
        ref($_) eq 'ARRAY'
          && @{$_} >= 2
          && (($_->[0] || '') eq 'topic')
          && (($_->[1] || '') eq $topic_text)
      } @{ $latest->{tags} || [] };
    },
  ), 'the relay exposes the latest authoritative metadata edit without the tombstone and with retained topic metadata';

  $drain_client_lines->($alice_a, 10);
  $drain_client_lines->($bob_b, 10);

  _write_client_line($bob_b, "LIST $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps LIST after the hosted channel is undeleted';
  my $undeleted_list_lines = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $undeleted_list_lines,
    'instance B emits a LIST response after the hosted channel is undeleted';
  is $undeleted_list_lines->[0], ":$server_name_b 321 bob Channel :Users Name",
    'instance B LIST starts normally after UNDELETE';
  like $undeleted_list_lines->[1],
    qr/\A:\Q$server_name_b\E 322 bob \Q$channel\E 0 :\Q$topic_text\E\z/,
    'instance B LIST rediscoveries the undeleted hosted channel with zero users and retained topic metadata';
  is $undeleted_list_lines->[2], ":$server_name_b 323 bob :End of /LIST",
    'instance B LIST ends normally after UNDELETE';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps JOIN against the undeleted hosted channel';
  my $undelete_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host_b],
    client          => $bob_b,
    count           => 4,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $undelete_join_bootstrap,
    'instance B emits the JOIN bootstrap after UNDELETE';
  is_deeply $undelete_join_bootstrap, [
    ":bob JOIN $channel",
    ":alice TOPIC $channel :$topic_text",
    ":$server_name_b 353 bob = $channel :bob",
    ":$server_name_b 366 bob $channel :End of /NAMES list.",
  ], 'UNDELETE restores retained topic metadata and durable membership but requires fresh presence after JOIN';

  _write_client_line($alice_a, "NAMES $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps authoritative NAMES after the retained member rejoins';
  is_deeply(
    _pump_hosts_until_client_lines(
      hosts           => [ $host_a, $host_b ],
      client          => $alice_a,
      count           => 2,
      pump_timeout_ms => $relay_host_pump_ms,
      timeout_ms      => $relay_propagation_timeout_ms,
    ),
    [
      ":$server_name_a 353 alice = $channel :bob",
      ":$server_name_a 366 alice $channel :End of /NAMES list.",
    ],
    'the retained member rejoin repopulates authoritative presence across instances after UNDELETE',
  );

  my $shutdown_a = $host_a->request_shutdown(reason => 'undeleted hosted channel test complete');
  is $shutdown_a->{state}, 'shutdown_complete', 'instance A undelete server handles runtime shutdown';
  is $shutdown_a->{exit_code}, 0, 'instance A undelete server exits cleanly';
  my $shutdown_b = $host_b->request_shutdown(reason => 'undeleted hosted channel test complete');
  is $shutdown_b->{state}, 'shutdown_complete', 'instance B undelete server handles runtime shutdown';
  is $shutdown_b->{exit_code}, 0, 'instance B undelete server exits cleanly';

  close $alice_a->{socket};
  close $bob_b->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

if (_run_program_irc_server_group('relay')) {
subtest 'IRC server program enforces authoritative bans across two instances' => sub {
  my $network = 'irc.authority.ban.test';
  my $channel = '#ops';
  my $group_host = 'groups.example.test';
  my $group_id = 'ops';
  my $relay_host_pump_ms = 1_500;
  my $relay_propagation_timeout_ms = 5_000;
  my $relay_port = _free_port();
  my $relay_url = "ws://127.0.0.1:$relay_port";
  my $server_name_a = 'overnet-ban-a.irc.local';
  my $server_name_b = 'overnet-ban-b.irc.local';
  my $bob_mask = 'bob!bob@127.0.0.1';

  my $alice_key = Net::Nostr::Key->new;
  my $bob_key   = Net::Nostr::Key->new;
  my $alice_pubkey = $alice_key->pubkey_hex;
  my $bob_pubkey   = $bob_key->pubkey_hex;

  my $relay = _spawn_authoritative_nip29_relay(
    port      => $relay_port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my @seed_events = (
    Net::Nostr::Group->metadata(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_300,
    )->to_hash,
    Net::Nostr::Group->admins(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_301,
      members    => [
        {
          pubkey => $alice_pubkey,
          roles  => ['irc.operator'],
        },
      ],
    )->to_hash,
    Net::Nostr::Group->members(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_302,
      members    => [
        $alice_pubkey,
      ],
    )->to_hash,
    Net::Nostr::Group->roles(
      pubkey     => 'f' x 64,
      group_id   => $group_id,
      created_at => 1_744_301_303,
      roles      => [
        { name => 'irc.operator' },
        { name => 'irc.voice' },
      ],
    )->to_hash,
  );
  my $seed_key = Net::Nostr::Key->new;
  @seed_events = map {
    $seed_key->create_event(
      kind       => $_->{kind},
      created_at => $_->{created_at},
      content    => $_->{content},
      tags       => $_->{tags},
    )->to_hash
  } @seed_events;

  for my $event (@seed_events) {
    my $publish = _publish_nostr_event_to_relay(
      relay_url => $relay_url,
      event     => $event,
    );
    ok $publish->{accepted}, 'relay accepts seeded authoritative state for the ban test';
  }

  my $build_runtime = sub {
    my (%args) = @_;
    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_path = File::Spec->catfile($tmpdir, $args{name} . '-irc-server-key.pem');
    my $key = Net::Nostr::Key->new;
    $key->save_privkey($key_path);

    my $runtime = Overnet::Program::Runtime->new(
      config => {
        adapter_id       => $args{adapter_id},
        network          => $network,
        listen_host      => '127.0.0.1',
        listen_port      => 0,
        server_name      => $args{server_name},
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
          url              => $relay_url,
          poll_interval_ms => 50,
        },
      },
    );
    ok $runtime->register_adapter_definition(
      adapter_id => $args{adapter_id},
      definition => {
        kind             => 'class',
        class            => 'Overnet::Adapter::IRC',
        lib_dirs         => [$irc_lib],
        constructor_args => {},
      },
    ), "$args{name} runtime can register the real authoritative IRC adapter";

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
        'adapters.open_session'        => {},
        'adapters.map_input'           => {},
        'adapters.derive'              => {},
        'adapters.close_session'       => {},
        'events.append'                => {},
        'events.read'                  => {},
        'nostr.publish_event'          => {},
        'nostr.query_events'           => {},
        'nostr.open_subscription'      => {},
        'nostr.read_subscription_snapshot' => {},
        'nostr.close_subscription'     => {},
        'subscriptions.open'           => {},
        'subscriptions.close'          => {},
        'overnet.emit_event'           => {},
        'overnet.emit_state'           => {},
        'overnet.emit_private_message' => {},
        'overnet.emit_capabilities'    => {},
      },
      startup_timeout_ms  => 1_000,
      shutdown_timeout_ms => 1_000,
    );

    $host->start;
    is $host->state, 'ready', "$args{name} authoritative ban server reaches ready state";
    my $ready = _wait_for_ready_details($host);
    ok $ready, "$args{name} authoritative ban server publishes ready health details";

    return ($runtime, $host, $ready);
  };

  my ($runtime_a, $host_a, $ready_a) = $build_runtime->(
    name        => 'ban-instance-a',
    adapter_id  => 'irc.authoritative.ban.a',
    server_name => $server_name_a,
  );
  my ($runtime_b, $host_b, $ready_b) = $build_runtime->(
    name        => 'ban-instance-b',
    adapter_id  => 'irc.authoritative.ban.b',
    server_name => $server_name_b,
  );

  my $alice_a = _connect_irc_client($ready_a->{listen_port});
  my $bob_b   = _connect_irc_client($ready_b->{listen_port});

  my $register = sub {
    my (%args) = @_;
    _write_client_line($args{client}, "NICK $args{nick}");
    _write_client_line($args{client}, "USER $args{nick} 0 * :$args{realname}");
    _assert_registration_prelude(
      client      => $args{client},
      nick        => $args{nick},
      network     => $network,
      server_name => $args{server_name},
      timeout_ms  => 3_000,
    );
  };

  my $authenticate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH CHALLENGE');
    my $challenge_line = _read_client_line($args{client}, 1_000);
    like $challenge_line, qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH CHALLENGE [0-9a-f]{64}\z/,
      "$args{nick} receives an authoritative auth challenge on $args{name}";
    $challenge_line =~ /([0-9a-f]{64})\z/;
    my $challenge = $1;
    _write_client_line($args{client}, 'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $args{key},
      challenge => $challenge,
      scope     => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
    ));
    is _read_client_line($args{client}, 1_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH AUTH $args{pubkey}",
      "$args{nick} authenticates an authoritative pubkey on $args{name}";
  };

  my $delegate = sub {
    my (%args) = @_;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE');
    my $delegate_line = _read_client_line($args{client}, 3_000);
    like $delegate_line,
      qr/\A:\Q$args{server_name}\E NOTICE \Q$args{nick}\E :OVERNETAUTH DELEGATE ([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/,
      "$args{nick} receives session delegation parameters on $args{name}";
    my ($delegate_pubkey, $session_id, $expires_at) = $delegate_line =~ /([0-9a-f]{64}) ([0-9a-f]{64}) \Q$relay_url\E (\d+)\z/;
    _write_client_line($args{client}, 'OVERNETAUTH DELEGATE ' . _build_authoritative_delegate_payload(
      key             => $args{key},
      relay_url       => $relay_url,
      scope           => _authoritative_auth_scope(
        server_name => $args{server_name},
        network     => $network,
      ),
      delegate_pubkey => $delegate_pubkey,
      session_id      => $session_id,
      expires_at      => $expires_at,
      nick            => $args{nick},
    ));
    ok $args{host}->pump(timeout_ms => $relay_host_pump_ms) >= 0,
      "$args{nick} pumps the authoritative delegation publish on $args{name}";
    is _read_client_line($args{client}, 3_000),
      ":$args{server_name} NOTICE $args{nick} :OVERNETAUTH DELEGATE",
      "$args{nick} establishes a session delegation grant on $args{name}";
  };

  $register->(
    client      => $alice_a,
    nick        => 'alice',
    realname    => 'Alice Ban',
    server_name => $server_name_a,
  );
  ok _wait_for_dm_subscription_count($host_a, 1),
    'instance A alice registration completes its DM subscription open';

  $register->(
    client      => $bob_b,
    nick        => 'bob',
    realname    => 'Bob Ban',
    server_name => $server_name_b,
  );
  ok _wait_for_dm_subscription_count($host_b, 1),
    'instance B bob registration completes its DM subscription open';

  $authenticate->(
    name        => 'instance A',
    client      => $alice_a,
    nick        => 'alice',
    key         => $alice_key,
    pubkey      => $alice_pubkey,
    server_name => $server_name_a,
  );
  $authenticate->(
    name        => 'instance B',
    client      => $bob_b,
    nick        => 'bob',
    key         => $bob_key,
    pubkey      => $bob_pubkey,
    server_name => $server_name_b,
  );
  $delegate->(
    name        => 'instance A',
    client      => $alice_a,
    host        => $host_a,
    nick        => 'alice',
    key         => $alice_key,
    server_name => $server_name_a,
  );
  $delegate->(
    name        => 'instance B',
    client      => $bob_b,
    host        => $host_b,
    nick        => 'bob',
    key         => $bob_key,
    server_name => $server_name_b,
  );

  _write_client_line($alice_a, "JOIN $channel");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps the operator join before setting bans';
  my $alice_ban_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [$host_a],
    client          => $alice_a,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $alice_ban_join_bootstrap,
    'instance A emits the operator bootstrap before authoritative bans';
  is_deeply $alice_ban_join_bootstrap, [
    ":alice JOIN $channel",
    ":$server_name_a 353 alice = $channel :\@alice",
    ":$server_name_a 366 alice $channel :End of /NAMES list.",
  ], 'alice receives JOIN plus operator-prefixed NAMES bootstrap on instance A';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps the initial open-channel join before banning bob';
  my $bob_ban_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [ $host_a, $host_b ],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $bob_ban_join_bootstrap,
    'instance B emits the initial open-channel JOIN bootstrap before the ban';
  is_deeply $bob_ban_join_bootstrap, [
    ":bob JOIN $channel",
    ":$server_name_b 353 bob = $channel :\@alice bob",
    ":$server_name_b 366 bob $channel :End of /NAMES list.",
  ], 'bob receives the initial JOIN bootstrap with retained remote presence on instance B before the ban';

  _write_client_line($alice_a, "MODE $channel +b $bob_mask");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps authoritative MODE +b';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":alice MODE $channel +b $bob_mask" ? 1 : 0;
    },
  ), 'alice sees the authoritative +b MODE line on instance A';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($bob_b, 50);
      return defined($line) && $line eq ":alice MODE $channel +b $bob_mask" ? 1 : 0;
    },
  ), 'bob sees the propagated authoritative +b MODE line on instance B';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_mode_write_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{mode} || '') eq '+b')
        && ref($_[0]{input}{mode_args}) eq 'ARRAY'
        && (($_[0]{input}{mode_args}[0] || '') eq $bob_mask);
    },
  ) >= 1, 'instance A derives authoritative ban-set permission through the adapter';

  my $relay_ban_events = _query_nostr_events_from_relay(
    relay_url => $relay_url,
    filters   => [
      {
        kinds => [9002],
        '#h'  => [$group_id],
        limit => 20,
      },
    ],
  );
  ok(
    scalar(grep {
      my %tags = _first_tag_values($_->{tags});
      my @ban_tags = map { $_->[1] }
        grep { ref($_) eq 'ARRAY' && (($_->[0] || '') eq 'ban') && defined $_->[1] }
        @{$_->{tags} || []};
      defined($tags{overnet_actor}) && $tags{overnet_actor} eq $alice_pubkey
        && scalar(grep { $_ eq $bob_mask } @ban_tags);
    } @{$relay_ban_events}),
    'the relay exposes an authoritative metadata edit carrying the new ban mask',
  );

  _write_client_line($bob_b, "MODE $channel +b");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps the authoritative ban-list query';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 367 bob $channel $bob_mask $server_name_b 0",
    'instance B renders the propagated authoritative ban list entry';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 368 bob $channel :End of channel ban list",
    'instance B terminates the authoritative ban-list query';
  ok _request_count_matching(
    $host_b->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_ban_list_view')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel);
    },
  ) >= 1, 'instance B derives authoritative ban-list rendering through the adapter';

  _write_client_line($bob_b, "PART $channel :bye");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps the authoritative PART before the banned rejoin';
  is _read_client_line($bob_b, 3_000), ":bob PART $channel :bye",
    'bob receives his authoritative PART echo before rejoining';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps the banned rejoin attempt';
  is _read_client_line($bob_b, 3_000), ":$server_name_b 474 bob $channel :Cannot join channel (+b)",
    'instance B rejects the banned authoritative JOIN with 474';

  _write_client_line($alice_a, "MODE $channel -b $bob_mask");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps authoritative MODE -b';
  ok _pump_hosts_until(
    hosts           => [ $host_a, $host_b ],
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
    condition       => sub {
      my $line = _read_client_line_optional($alice_a, 50);
      return defined($line) && $line eq ":alice MODE $channel -b $bob_mask" ? 1 : 0;
    },
  ), 'alice sees the authoritative -b MODE line on instance A';
  ok _request_count_matching(
    $host_a->transcript,
    'from_program',
    'adapters.derive',
    sub {
      (($_[0]{operation} || '') eq 'authoritative_mode_write_permission')
        && ref($_[0]{input}) eq 'HASH'
        && (($_[0]{input}{target} || '') eq $channel)
        && (($_[0]{input}{actor_pubkey} || '') eq $alice_pubkey)
        && (($_[0]{input}{mode} || '') eq '-b')
        && ref($_[0]{input}{mode_args}) eq 'ARRAY'
        && (($_[0]{input}{mode_args}[0] || '') eq $bob_mask);
    },
  ) >= 1, 'instance A derives authoritative ban-clear permission through the adapter';

  my $propagated_part_before_unban_query = _read_client_line_optional($alice_a, 250);
  ok !defined($propagated_part_before_unban_query) || $propagated_part_before_unban_query eq ":bob PART $channel :bye",
    'instance A either consumes or has already rendered the propagated PART before the empty ban-list query';

  _write_client_line($alice_a, "MODE $channel +b");
  ok $host_a->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance A pumps the post-unban ban-list query';
  is _read_client_line($alice_a, 3_000), ":$server_name_a 368 alice $channel :End of channel ban list",
    'instance A reports an empty authoritative ban list after -b';

  my $relay_unban_events = _query_nostr_events_from_relay(
    relay_url => $relay_url,
    filters   => [
      {
        kinds => [9002],
        '#h'  => [$group_id],
        limit => 20,
      },
    ],
  );
  my @sorted_unban_events = sort {
    (($a->{created_at} || 0) <=> ($b->{created_at} || 0))
      || (($a->{id} || '') cmp ($b->{id} || ''))
  } @{$relay_unban_events};
  my $latest_unban_event = $sorted_unban_events[-1];
  ok $latest_unban_event, 'a latest authoritative metadata edit exists after -b';
  ok !scalar(grep {
    ref($_) eq 'ARRAY' && (($_->[0] || '') eq 'ban') && defined($_->[1]) && $_->[1] eq $bob_mask
  } @{$latest_unban_event->{tags} || []}),
    'the latest authoritative metadata edit no longer carries the removed ban mask';

  _write_client_line($bob_b, "JOIN $channel");
  ok $host_b->pump(timeout_ms => $relay_host_pump_ms) >= 0,
    'instance B pumps the post-unban rejoin';
  my $bob_unban_join_bootstrap = _pump_hosts_until_client_lines(
    hosts           => [ $host_a, $host_b ],
    client          => $bob_b,
    count           => 3,
    pump_timeout_ms => $relay_host_pump_ms,
    timeout_ms      => $relay_propagation_timeout_ms,
  );
  ok $bob_unban_join_bootstrap,
    'instance B emits the post-unban JOIN bootstrap';
  is_deeply $bob_unban_join_bootstrap, [
    ":bob JOIN $channel",
    ":$server_name_b 353 bob = $channel :\@alice bob",
    ":$server_name_b 366 bob $channel :End of /NAMES list.",
  ], 'bob can rejoin the authoritative channel with retained remote presence after the propagated -b';

  my $shutdown_a = $host_a->request_shutdown(reason => 'relay-backed authoritative ban test complete A');
  is $shutdown_a->{state}, 'shutdown_complete', 'instance A authoritative ban server handles runtime shutdown';
  is $shutdown_a->{exit_code}, 0, 'instance A authoritative ban server exits cleanly';

  my $shutdown_b = $host_b->request_shutdown(reason => 'relay-backed authoritative ban test complete B');
  is $shutdown_b->{state}, 'shutdown_complete', 'instance B authoritative ban server handles runtime shutdown';
  is $shutdown_b->{exit_code}, 0, 'instance B authoritative ban server exits cleanly';

  close $alice_a->{socket};
  close $bob_b->{socket};
  _stop_authoritative_nip29_relay($relay);
};
}

subtest 'IRC program entrypoints do not import Net::Nostr directly' => sub {
  my @paths = (
    File::Spec->catfile(
      $FindBin::Bin,
      '..',
      '..',
      'overnet-program-irc',
      'lib',
      'Overnet',
      'Program',
      'IRC',
      'Server.pm',
    ),
    File::Spec->catfile(
      $FindBin::Bin,
      '..',
      '..',
      'overnet-program-irc',
      'bin',
      'overnet-irc-local-server.pl',
    ),
    File::Spec->catfile(
      $FindBin::Bin,
      '..',
      '..',
      'overnet-program-irc',
      'bin',
      'overnet-irc-server.pl',
    ),
    File::Spec->catfile(
      $FindBin::Bin,
      '..',
      '..',
      'overnet-program-irc',
      'bin',
      'overnet-irc-chat-client.pl',
    ),
  );

  for my $path (@paths) {
    open my $fh, '<', $path
      or die "Unable to read $path: $!";
    my $source = do { local $/; <$fh> };
    close $fh;

    unlike $source, qr/^\s*use\s+Net::Nostr/m,
      "$path no longer imports Net::Nostr directly";
    unlike $source, qr/\bNet::Nostr::/,
      "$path no longer references Net::Nostr directly";
  }
};

subtest 'IRC server source keeps relay I/O and raw authoritative interpretation out of the program layer' => sub {
  my $server_path = File::Spec->catfile(
    $FindBin::Bin,
    '..',
    '..',
    'overnet-program-irc',
    'lib',
    'Overnet',
    'Program',
    'IRC',
    'Server.pm',
  );

  open my $fh, '<', $server_path
    or die "Unable to read $server_path: $!";
  my $source = do { local $/; <$fh> };
  close $fh;

  unlike $source, qr/Overnet::Core::Nostr->query_events/,
    'Server.pm does not query relays directly through Overnet::Core::Nostr';
  unlike $source, qr/Overnet::Core::Nostr->publish_event/,
    'Server.pm does not publish relay events directly through Overnet::Core::Nostr';
  unlike $source, qr/\b_authoritative_pending_invite_for_pubkey\b/,
    'Server.pm does not keep a raw pending-invite scanner';
  unlike $source, qr/\b_authoritative_present_pubkeys_for_channel\b/,
    'Server.pm does not keep a raw present-member scanner';
};

done_testing;
