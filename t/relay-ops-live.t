use strict;
use warnings;

use AnyEvent;
use AnyEvent::WebSocket::Client;
use File::Spec;
use FindBin;
use IO::Socket::INET;
use IPC::Open3 qw(open3);
use JSON::PP qw(decode_json encode_json);
use Net::Nostr::Event;
use Net::Nostr::Key;
use Net::Nostr::Message;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

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
  my @command = (
    $^X,
    $relay_script,
    '--host', '127.0.0.1',
    '--port', $args{port},
    '--name', 'Overnet Relay Ops Test',
    '--description', 'Relay ops live tests',
    '--software', 'https://example.invalid/overnet-relay',
    '--version', '0.1.0-test',
  );
  push @command, @{$args{extra_args} || []};

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
    if ($ok) {
      return 1;
    }
    sleep 0.05;
  }

  die "relay process did not become ready on port $port\n";
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

sub _create_overnet_event {
  my (%args) = @_;
  return $args{key}->create_event(
    kind => 7800,
    tags => [
      ['overnet_v', '0.1.0'],
      ['overnet_et', 'chat.message'],
      ['overnet_ot', 'chat.channel'],
      ['overnet_oid', 'irc:live:#ops'],
      ['v', '0.1.0'],
      ['t', 'chat.message'],
      ['o', 'chat.channel'],
      ['d', 'irc:live:#ops'],
    ],
    content => encode_json({
      provenance => { type => 'native' },
      body       => { text => $args{text} },
    }),
  );
}

sub _connect_ws {
  my ($port, $callback) = @_;
  my $client = AnyEvent::WebSocket::Client->new;
  my $holder;
  my $cv = AnyEvent->condvar;
  my $timeout;
  $timeout = AnyEvent->timer(
    after => 5,
    cb => sub {
      undef $timeout;
      $cv->send({ ok => 0, error => "websocket connect timed out\n" });
    },
  );
  $client->connect("ws://127.0.0.1:$port")->cb(sub {
    my $conn = eval { shift->recv };
    if ($@) {
      undef $timeout;
      $cv->send({ ok => 0, error => "$@" });
      return;
    }
    my $t;
    $t = AnyEvent->timer(
      after => 0.05,
      cb => sub {
        undef $t;
        $callback->($conn) if $callback;
      },
    );
    $holder = [$client, $conn, $t];
    undef $timeout;
    $cv->send({ ok => 1, client => $client, conn => $conn, holder => \$holder });
  });
  return $cv->recv;
}

subtest 'relay CLI exposes deploy-time operational controls' => sub {
  my $stderr = gensym();
  my $pid = open3(
    undef,
    my $stdout,
    $stderr,
    $^X,
    $relay_script,
    '--help',
  );
  my $stdout_text = do { local $/; <$stdout> };
  close $stdout;
  close $stderr;
  waitpid($pid, 0);

  like $stdout_text, qr/--max-connections-per-ip\b/, 'relay help exposes connection caps';
  like $stdout_text, qr/--event-rate-limit\b/, 'relay help exposes event rate limiting';
  like $stdout_text, qr/--min-pow-difficulty\b/, 'relay help exposes PoW control';
  like $stdout_text, qr/--service-policy\b/, 'relay help exposes service policy control';
};

subtest 'relay enforces max-connections-per-ip' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(
    port => $port,
    extra_args => ['--max-connections-per-ip', '1'],
  );
  eval {
    _wait_for_relay_ready($port);

    my $first = _connect_ws($port);
    ok $first->{ok}, 'first websocket connection succeeds';

    my $second = _connect_ws($port);
    ok !$second->{ok}, 'second websocket connection is rejected by the connection cap';

    $first->{conn}->close if $first->{ok};
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

subtest 'relay enforces event rate limits on publish' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(
    port => $port,
    extra_args => ['--event-rate-limit', '1/60'],
  );
  eval {
    _wait_for_relay_ready($port);
    my @received;
    my $cv = AnyEvent->condvar;
    my $conn_result = _connect_ws($port, sub {
      my ($conn) = @_;
      my $phase = 'first';
      my $key = Net::Nostr::Key->new;
      my $first = _create_overnet_event(key => $key, text => 'first');
      my $second = _create_overnet_event(key => $key, text => 'second');

      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;

        if ($phase eq 'first' && $parsed->type eq 'OK') {
          $phase = 'second';
          $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $second)->serialize);
          return;
        }

        if ($phase eq 'second' && $parsed->type eq 'OK') {
          $cv->send;
        }
      });

      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $first)->serialize);
    });
    ok $conn_result->{ok}, 'websocket connection succeeds';
    $cv->recv;

    my @ok_messages = grep { $_->type eq 'OK' } @received;
    is scalar(@ok_messages), 2, 'rate-limit flow returns two OK messages';
    ok $ok_messages[0]->accepted, 'first publish is accepted';
    ok !$ok_messages[1]->accepted, 'second publish is rejected';
    like $ok_messages[1]->message, qr/rate limited/i, 'second publish reports rate limiting';

    $conn_result->{conn}->close;
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

subtest 'relay enforces closed publish and object-read service policies' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(
    port => $port,
    extra_args => [
      '--service-policy', 'publish=closed',
      '--service-policy', 'object_read=closed',
    ],
  );
  eval {
    _wait_for_relay_ready($port);
    my @received;
    my $cv = AnyEvent->condvar;
    my $conn_result = _connect_ws($port, sub {
      my ($conn) = @_;
      my $phase = 'publish';
      my $key = Net::Nostr::Key->new;
      my $event = _create_overnet_event(key => $key, text => 'blocked');

      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;

        if ($phase eq 'publish' && $parsed->type eq 'OK') {
          $cv->send;
        }
      });

      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $event)->serialize);
    });
    ok $conn_result->{ok}, 'websocket connection succeeds';
    $cv->recv;

    my ($ok) = grep { $_->type eq 'OK' } @received;
    ok !$ok->accepted, 'publish is rejected when publish policy is closed';
    like $ok->message, qr/policy_denied/i, 'publish rejection reports policy denial';
    $conn_result->{conn}->close;

    my $response = _http_request(
      port => $port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alive%3A%23ops HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: close',
        '',
        '',
      ),
    );
    like $response, qr/\AHTTP\/1\.[01] 403 /, 'closed object-read policy returns HTTP 403';
    my (undef, $body) = split /\r\n\r\n/, $response, 2;
    like $body, qr/policy_denied/i, 'object-read policy denial is reported in the body';
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

done_testing;
