use strict;
use warnings;

use AnyEvent;
use AnyEvent::WebSocket::Client;
use File::Spec;
use FindBin;
use IO::Socket::INET;
use IPC::Open3 qw(open3);
use JSON::PP qw(decode_json encode_json);
use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Message;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

use Overnet::Relay::Sync;

my $relay_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay.pl');

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

sub _spawn_relay_process {
  my (%args) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    $^X,
    $relay_script,
    '--host', '127.0.0.1',
    '--port', $args{port},
    '--name', $args{name},
    '--description', 'Live relay sync test process',
    '--software', 'https://example.invalid/overnet-relay',
    '--version', '0.1.0-test',
    '--max-negentropy-sessions', 4,
    '--max-filters', 8,
    '--max-limit', 100,
    '--max-subscriptions', 8,
    '--max-message-length', 65536,
    '--max-content-length', 32768,
  );

  close $stdin;

  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
    port   => $args{port},
  };
}

sub _stop_relay_process {
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

sub _wait_for_relay_ready {
  my ($port) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $ok = eval {
      my $socket = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 1,
      ) or die "connect failed: $!";
      binmode($socket, ':raw');
      $socket->autoflush(1);
      print {$socket} join(
        "\r\n",
        'GET / HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/nostr+json',
        'Connection: close',
        '',
        '',
      ) or die "request failed: $!";
      my $response = do { local $/; <$socket> };
      close $socket;
      return defined $response && $response =~ /\AHTTP\/1\.[01] 200 / ? 1 : 0;
    };

    return 1 if $ok;
    sleep 0.05;
  }

  die "relay did not become ready on port $port\n";
}

sub _http_request {
  my (%args) = @_;
  my $socket = IO::Socket::INET->new(
    PeerHost => '127.0.0.1',
    PeerPort => $args{port},
    Proto    => 'tcp',
    Timeout  => 1,
  ) or die "Can't connect to relay HTTP port $args{port}: $!";

  binmode($socket, ':raw');
  $socket->autoflush(1);
  print {$socket} $args{request}
    or die "Can't write HTTP request to relay: $!";

  my $response = do { local $/; <$socket> };
  close $socket;
  return $response;
}

sub _decode_http_json_body {
  my ($response) = @_;
  my (undef, $body) = split /\r\n\r\n/, $response, 2;
  return decode_json($body);
}

sub _connect_ws {
  my ($port, $callback) = @_;

  my $client = AnyEvent::WebSocket::Client->new;
  my $holder;
  $client->connect("ws://127.0.0.1:$port")->cb(sub {
    my $conn = eval { shift->recv };
    die "WebSocket connect failed: $@" unless $conn;

    my $t;
    $t = AnyEvent->timer(
      after => 0.15,
      cb => sub {
        undef $t;
        $callback->($conn);
      },
    );
    $holder = [$client, $conn, $t];
  });

  return \$holder;
}

sub _create_overnet_event {
  my (%args) = @_;
  my @tags = (
    ['overnet_v', '0.1.0'],
    ['overnet_et', $args{event_type}],
    ['overnet_ot', $args{object_type}],
    ['overnet_oid', $args{object_id}],
    ['v', '0.1.0'],
    ['t', $args{event_type}],
    ['o', $args{object_type}],
    ['d', $args{object_id}],
  );

  return $args{key}->create_event(
    kind => $args{kind},
    tags => \@tags,
    content => encode_json({
      provenance => { type => 'native' },
      body       => $args{body},
    }),
  );
}

subtest 'one-shot negentropy sync pulls a missing Overnet event into a second live relay' => sub {
  my $relay_a_port = _free_port();
  my $relay_b_port = _free_port();

  my $relay_a = _spawn_relay_process(port => $relay_a_port, name => 'Overnet Relay A');
  my $relay_b = _spawn_relay_process(port => $relay_b_port, name => 'Overnet Relay B');

  eval {
    _wait_for_relay_ready($relay_a_port);
    _wait_for_relay_ready($relay_b_port);

    my $author = Net::Nostr::Key->new;
    my $event = _create_overnet_event(
      key         => $author,
      kind        => 37800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => 'irc:sync:#overnet',
      body        => { text => 'Synced Topic' },
    );

    my $publish_cv = AnyEvent->condvar;
    my $publish_ref = _connect_ws($relay_a_port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        $publish_cv->send($parsed) if $parsed->type eq 'OK';
      });
      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $event)->serialize);
    });

    my $publish_ok = $publish_cv->recv;
    ok $publish_ref, 'websocket client stays alive for relay A publish';
    ok $publish_ok->accepted, 'relay A accepts the published event';

    my $sync = Overnet::Relay::Sync->new(local_url => "ws://127.0.0.1:$relay_b_port");
    my $result = $sync->sync_once(
      remote_url => "ws://127.0.0.1:$relay_a_port",
      local_url => "ws://127.0.0.1:$relay_b_port",
      filter => Net::Nostr::Filter->new(
        kinds => [37800],
        '#t'  => ['chat.topic'],
        '#o'  => ['chat.channel'],
        '#d'  => ['irc:sync:#overnet'],
      ),
    );

    is_deeply $result->{need_ids}, [$event->id], 'negentropy reports the missing event id';
    is_deeply $result->{fetched_ids}, [$event->id], 'sync fetches the missing event by id';
    is_deeply $result->{stored_ids}, [$event->id], 'sync stores the missing event locally';
    is $result->{negentropy_rounds}, 1, 'simple one-event sync completes in one negentropy round';

    my @received;
    my $query_cv = AnyEvent->condvar;
    my $query_ref = _connect_ws($relay_b_port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;
        $query_cv->send if $parsed->type eq 'EOSE';
      });
      my $filter = Net::Nostr::Filter->new(
        kinds => [37800],
        '#overnet_et' => ['chat.topic'],
        '#overnet_ot' => ['chat.channel'],
        '#overnet_oid' => ['irc:sync:#overnet'],
      );
      $conn->send(Net::Nostr::Message->new(
        type            => 'REQ',
        subscription_id => 'relay-b-sub',
        filters         => [$filter],
      )->serialize);
    });
    $query_cv->recv;
    ok $query_ref, 'websocket client stays alive for relay B query';

    my ($event_msg) = grep { $_->type eq 'EVENT' } @received;
    my ($eose_msg) = grep { $_->type eq 'EOSE' } @received;
    ok $event_msg, 'relay B returns the synced event over REQ';
    is $event_msg->event->id, $event->id, 'relay B query returns the synced event id';
    ok $eose_msg, 'relay B query returns EOSE';

    my $response = _http_request(
      port => $relay_b_port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Async%3A%23overnet HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/json',
        'Connection: close',
        '',
        '',
      ),
    );
    like $response, qr/\AHTTP\/1\.[01] 200 /, 'relay B object endpoint returns HTTP 200 after sync';
    my $body = _decode_http_json_body($response);
    is $body->{state_event}{id}, $event->id, 'relay B object endpoint exposes the synced state event';
  };
  my $error = $@;
  _stop_relay_process($relay_a);
  _stop_relay_process($relay_b);
  die $error if $error;
};

done_testing;
