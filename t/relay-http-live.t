use strictures 2;

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket qw(tcp_connect);
use AnyEvent::WebSocket::Client;
use IO::Socket::INET;
use JSON ();
use Test2::V0;

use Net::Nostr::Key;
use Overnet::Relay;

# This suite runs the relay inside the test process so the socket-level
# HTTP/WebSocket dispatch is exercised directly rather than in a child
# process.
my $JSON          = JSON->new->utf8->canonical;
my $TIMEOUT_SCALE = $INC{'Devel/Cover.pm'} ? 30 : 1;

sub _scaled_s {
  my ($seconds) = @_;
  return $seconds * $TIMEOUT_SCALE;
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

my $PORT  = _free_port();
my $RELAY = Overnet::Relay->new(
  relay_url               => "ws://127.0.0.1:$PORT",
  name                    => 'Overnet HTTP Live Relay',
  description             => 'In-process socket dispatch coverage',
  profile_contract_policy => 'off',
);
$RELAY->start('127.0.0.1', $PORT);

# Sends raw bytes and returns everything the relay writes until it closes the
# connection (undef on timeout). The relay closes plain HTTP exchanges itself.
sub _raw_exchange {
  my (%args) = @_;
  my $cv = AnyEvent->condvar;
  my $received = q{};
  my ($handle, $timer);

  my $finish = sub {
    my ($result) = @_;
    undef $handle;
    undef $timer;
    $cv->send($result);
  };

  # give_up_seconds is used verbatim: waits keyed to the relay's own real-time
  # timers must not stretch under instrumentation.
  $timer = AnyEvent->timer(
    after => $args{give_up_seconds} // _scaled_s(15),
    cb    => sub { $finish->(undef) },
  );

  tcp_connect '127.0.0.1', $PORT, sub {
    my ($fh) = @_;
    if (!$fh) {
      $finish->(undef);
      return;
    }
    $handle = AnyEvent::Handle->new(
      fh       => $fh,
      on_error => sub { $finish->($received) },
      on_eof   => sub { $finish->($received) },
      on_read  => sub {
        my ($h) = @_;
        $received .= $h->rbuf;
        $h->rbuf = q{};
      },
    );
    if (length($args{send} // q{})) {
      $handle->push_write($args{send});
    }
  };

  return $cv->recv;
}

sub _http_request_text {
  my (%args) = @_;
  my @lines = (
    "$args{method} $args{path} HTTP/1.1",
    'Host: 127.0.0.1',
    @{$args{headers} || []},
    'Connection: close',
  );
  return join("\r\n", @lines) . "\r\n\r\n";
}

subtest 'OPTIONS requests receive a CORS preflight response' => sub {
  my $response = _raw_exchange(send => _http_request_text(method => 'OPTIONS', path => '/'));
  like $response, qr/\AHTTP\/1\.1\ 204\ /mx, 'preflight returns 204';
  like $response, qr/Access-Control-Allow-Origin:\ \*/mx, 'preflight allows any origin';
};

subtest 'the object endpoint is dispatched from the socket layer' => sub {
  my $key   = Net::Nostr::Key->new;
  my $state = $key->create_event(
    kind => 37800,
    tags => [
      ['overnet_v',   '0.1.0'],
      ['overnet_et',  'chat.topic'],
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:local:#live'],
      ['v',           '0.1.0'],
      ['t',           'chat.topic'],
      ['o',           'chat.channel'],
      ['d',           'irc:local:#live'],
    ],
    content => $JSON->encode({provenance => {type => 'native'}, body => {text => 'Live'}}),
  );
  $RELAY->store->store($state);

  my $response = _raw_exchange(
    send => _http_request_text(
      method => 'GET',
      path   => '/.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alocal%3A%23live',
    ),
  );
  like $response, qr/\AHTTP\/1\.1\ 200\ /mx, 'object view returns 200';
  my (undef, $body) = split /\r\n\r\n/mx, $response, 2;
  is $JSON->decode($body)->{state_event}{id}, $state->id, 'object view returns the state event';

  my $rejected = _raw_exchange(
    send => _http_request_text(
      method => 'POST',
      path   => '/.well-known/overnet/v1/object?type=chat.channel&id=x',
    ),
  );
  like $rejected, qr/\AHTTP\/1\.1\ 405\ /mx, 'non-GET object requests are rejected at the socket layer';
};

subtest 'NIP-11 requests receive the relay information document' => sub {
  my $response = _raw_exchange(
    send => _http_request_text(
      method  => 'GET',
      path    => '/',
      headers => ['Accept: application/nostr+json'],
    ),
  );
  like $response, qr/\AHTTP\/1\.1\ 200\ /mx, 'NIP-11 request returns 200';
  my (undef, $body) = split /\r\n\r\n/mx, $response, 2;
  is $JSON->decode($body)->{name}, 'Overnet HTTP Live Relay', 'information document is served';
};

subtest 'unknown HTTP endpoints return 404' => sub {
  my $response = _raw_exchange(send => _http_request_text(method => 'GET', path => '/nope'));
  like $response, qr/\AHTTP\/1\.1\ 404\ /mx, 'unknown endpoint returns 404';
  like $response, qr/Unknown\ HTTP\ endpoint/mx, '404 body names the failure';
};

subtest 'WebSocket upgrades reach the Nostr protocol layer' => sub {
  my $client = AnyEvent::WebSocket::Client->new(timeout => _scaled_s(15));
  my $conn   = $client->connect("ws://127.0.0.1:$PORT")->recv;
  ok $conn, 'WebSocket connection is established';

  my $cv    = AnyEvent->condvar;
  my $timer = AnyEvent->timer(after => _scaled_s(15), cb => sub { $cv->send(undef) });
  my @frames;
  $conn->on(
    each_message => sub {
      my (undef, $message) = @_;
      push @frames, JSON::decode_json($message->body);
      if ($frames[-1][0] eq 'EOSE') {
        $cv->send(1);
      }
    }
  );
  $conn->send($JSON->encode(['REQ', 'live-sub', {kinds => [37800]}]));
  ok $cv->recv, 'the relay answered the REQ through EOSE';
  ok((grep { $_->[0] eq 'EVENT' } @frames), 'the stored state event is served over WS');
  $conn->close;
};

subtest 'oversized headerless requests are dispatched as WebSocket attempts' => sub {
  # 8 KiB of bytes with no header terminator forces the buffered dispatch
  # path without matching any HTTP route.
  _raw_exchange(send => 'X' x 8_192, give_up_seconds => 5);

  my $check = _raw_exchange(send => _http_request_text(method => 'OPTIONS', path => '/'));
  like $check, qr/\AHTTP\/1\.1\ 204\ /mx, 'the relay still answers after the garbage request';
};

subtest 'silent connections fall through to WebSocket handling after the grace period' => sub {
  # The relay arms a 5 real-second timer for connections that send nothing;
  # hold one open past that deadline so the timer path runs.
  my $response = _raw_exchange(send => q{}, give_up_seconds => 8);
  ok !length($response // q{}), 'a silent connection receives no HTTP response';

  my $check = _raw_exchange(send => _http_request_text(method => 'OPTIONS', path => '/'));
  like $check, qr/\AHTTP\/1\.1\ 204\ /mx, 'the relay still answers after the silent connection';
};

done_testing;
