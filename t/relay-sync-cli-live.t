use strict;
use warnings;

use AnyEvent;
use AnyEvent::WebSocket::Client;
use File::Spec;
use File::Temp qw(tempdir);
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

my $relay_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay.pl');
my $sync_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay-sync.pl');

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
    '--description', 'Live relay sync CLI test process',
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

sub _wait_for_relay_ready {
  my ($port) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $ok = eval {
      my $response = _http_request(
        port => $port,
        request => join(
          "\r\n",
          'GET / HTTP/1.1',
          'Host: 127.0.0.1',
          'Accept: application/nostr+json',
          'Connection: close',
          '',
          '',
        ),
      );
      return defined $response && $response =~ /\AHTTP\/1\.[01] 200 / ? 1 : 0;
    };

    return 1 if $ok;
    sleep 0.05;
  }

  die "relay process did not become ready on port $port\n";
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

ok -f $sync_script, 'relay sync CLI launcher exists';

subtest 'relay sync CLI loads static config and syncs one peer into the local relay' => sub {
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
      object_id   => 'irc:sync:#cli',
      body        => { text => 'CLI Topic' },
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

    my $tempdir = tempdir(CLEANUP => 1);
    my $config_path = File::Spec->catfile($tempdir, 'relay-sync.json');
    open my $config_fh, '>:raw', $config_path
      or die "Can't create relay sync config: $!";
    print {$config_fh} encode_json({
      local_url => "ws://127.0.0.1:$relay_b_port",
      timeout_seconds => 5,
      peers => [
        {
          name => 'relay-a',
          remote_url => "ws://127.0.0.1:$relay_a_port",
          subscription_id => 'relay-a-sync',
          filter => {
            kinds => [37800],
            '#t'  => ['chat.topic'],
            '#o'  => ['chat.channel'],
            '#d'  => ['irc:sync:#cli'],
          },
        },
      ],
    }) or die "Can't write relay sync config: $!";
    close $config_fh;

    my $stderr = gensym();
    my $pid = open3(
      my $stdin,
      my $stdout,
      $stderr,
      $^X,
      $sync_script,
      '--config', $config_path,
    );
    close $stdin;
    my $sync_stdout = do { local $/; <$stdout> };
    my $sync_stderr = do { local $/; <$stderr> };
    close $stdout;
    close $stderr;
    waitpid($pid, 0);
    is $? >> 8, 0, 'relay sync CLI exits successfully'
      or diag $sync_stderr;
    ok defined($sync_stdout) && length($sync_stdout), 'relay sync CLI prints JSON summary';

    my $summary = decode_json($sync_stdout);
    is $summary->{local_url}, "ws://127.0.0.1:$relay_b_port", 'summary records local relay URL';
    is $summary->{peer_count}, 1, 'summary reports one configured peer';
    is $summary->{results}[0]{name}, 'relay-a', 'summary records peer name';
    is_deeply $summary->{results}[0]{need_ids}, [$event->id], 'summary reports the missing id';
    is_deeply $summary->{results}[0]{stored_ids}, [$event->id], 'summary reports the stored id';

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
        '#overnet_oid' => ['irc:sync:#cli'],
      );
      $conn->send(Net::Nostr::Message->new(
        type            => 'REQ',
        subscription_id => 'relay-b-cli-sub',
        filters         => [$filter],
      )->serialize);
    });
    $query_cv->recv;
    ok $query_ref, 'websocket client stays alive for relay B query';

    my ($event_msg) = grep { $_->type eq 'EVENT' } @received;
    ok $event_msg, 'relay B returns the synced event after CLI sync';
    is $event_msg->event->id, $event->id, 'relay B query returns the CLI-synced event id';

    my $response = _http_request(
      port => $relay_b_port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Async%3A%23cli HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/json',
        'Connection: close',
        '',
        '',
      ),
    );
    like $response, qr/\AHTTP\/1\.[01] 200 /, 'relay B object endpoint returns HTTP 200 after CLI sync';
    my $body = _decode_http_json_body($response);
    is $body->{state_event}{id}, $event->id, 'relay B object endpoint exposes the CLI-synced state event';
  };
  my $error = $@;
  _stop_relay_process($relay_a);
  _stop_relay_process($relay_b);
  die $error if $error;
};

done_testing;
