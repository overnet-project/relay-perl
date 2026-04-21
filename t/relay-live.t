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
use Net::Nostr::Negentropy;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

my $relay_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay.pl');
my $relay_backup_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay-backup.pl');

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
    '--name', 'Overnet Live Relay',
    '--description', 'Live relay test process',
    '--software', 'https://example.invalid/overnet-relay',
    '--version', '0.1.0-test',
    '--max-negentropy-sessions', 4,
    (defined $args{store_file} ? ('--store-file', $args{store_file}) : ()),
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

sub _decode_http_json_body {
  my ($response) = @_;
  my (undef, $body) = split /\r\n\r\n/, $response, 2;
  return decode_json($body);
}

sub _run_relay_backup {
  my (%args) = @_;
  my $stderr = gensym();
  my $pid = open3(
    undef,
    my $stdout,
    $stderr,
    $^X,
    $relay_backup_script,
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

ok -f $relay_script, 'relay launcher script exists';
ok -f $relay_backup_script, 'relay backup script exists';

subtest 'relay process serves NIP-11 and supports live publish/query over WebSocket' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(port => $port);
  eval {
    _wait_for_relay_ready($port);

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
    like $response, qr/\AHTTP\/1\.[01] 200 /, 'NIP-11 endpoint returns HTTP 200';
    my $body = _decode_http_json_body($response);
    ok grep($_ == 77, @{$body->{supported_nips} || []}), 'NIP-11 metadata includes NIP-77';
    ok grep($_ eq 'overnet.events.sync', @{$body->{overnet}{capabilities} || []}),
      'NIP-11 metadata includes overnet.events.sync';

    my $author = Net::Nostr::Key->new;
    my $event = _create_overnet_event(
      key         => $author,
      kind        => 7800,
      event_type  => 'chat.message',
      object_type => 'chat.channel',
      object_id   => 'irc:live:#overnet',
      body        => { text => 'hello live relay' },
    );

    my @received;
    my $cv = AnyEvent->condvar;
    my $conn_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      my $phase = 'publish';
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;

        if ($phase eq 'publish' && $parsed->type eq 'OK') {
          $phase = 'query';
          my $filter = Net::Nostr::Filter->new(
            kinds => [7800],
            '#overnet_et' => ['chat.message'],
            '#overnet_ot' => ['chat.channel'],
            '#overnet_oid' => ['irc:live:#overnet'],
          );
          $conn->send(Net::Nostr::Message->new(
            type            => 'REQ',
            subscription_id => 'live-sub',
            filters         => [$filter],
          )->serialize);
          return;
        }

        if ($phase eq 'query' && $parsed->type eq 'EOSE') {
          $cv->send;
        }
      });

      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $event)->serialize);
    });

    $cv->recv;
    ok $conn_ref, 'websocket client stays alive for live publish/query';

    my ($ok_msg) = grep { $_->type eq 'OK' } @received;
    my ($event_msg) = grep { $_->type eq 'EVENT' } @received;
    my ($eose_msg) = grep { $_->type eq 'EOSE' } @received;

    ok $ok_msg, 'publish produced OK';
    ok $ok_msg->accepted, 'publish OK is accepted';
    is $ok_msg->event_id, $event->id, 'publish OK references event id';
    ok $event_msg, 'REQ returned an EVENT frame';
    is $event_msg->subscription_id, 'live-sub', 'EVENT uses request subscription id';
    is $event_msg->event->id, $event->id, 'REQ returned the published event';
    ok $eose_msg, 'REQ returned EOSE';
    is $eose_msg->subscription_id, 'live-sub', 'EOSE uses request subscription id';
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

subtest 'relay process serves live object reads over HTTP' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(port => $port);
  eval {
    _wait_for_relay_ready($port);

    my $author = Net::Nostr::Key->new;
    my $state_event = _create_overnet_event(
      key         => $author,
      kind        => 37800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => 'irc:live:#overnet',
      body        => { text => 'Live Topic' },
    );

    my $cv = AnyEvent->condvar;
    my $conn_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        $cv->send if $parsed->type eq 'OK' && $parsed->accepted;
      });
      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $cv->recv;
    ok $conn_ref, 'websocket client stays alive for object-read publish';

    my $response = _http_request(
      port => $port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alive%3A%23overnet HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/json',
        'Connection: close',
        '',
        '',
      ),
    );

    like $response, qr/\AHTTP\/1\.[01] 200 /, 'object endpoint returns HTTP 200';
    my $body = _decode_http_json_body($response);
    is $body->{object_type}, 'chat.channel', 'object type matches';
    is $body->{object_id}, 'irc:live:#overnet', 'object id matches';
    ok !$body->{removed}, 'object is not marked removed';
    is $body->{state_event}{id}, $state_event->id, 'state_event id matches the published state';
    is $body->{removal_event}, undef, 'no removal event present';
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

subtest 'relay process persists live object state across restart and suppresses duplicate replay' => sub {
  my $tmpdir = tempdir(CLEANUP => 1);
  my $store_file = File::Spec->catfile($tmpdir, 'relay-store.json');
  my $port = _free_port();
  my $proc = _spawn_relay_process(
    port       => $port,
    store_file => $store_file,
  );
  eval {
    _wait_for_relay_ready($port);

    my $author = Net::Nostr::Key->new;
    my $state_event = _create_overnet_event(
      key         => $author,
      kind        => 37800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => 'irc:live:#persist',
      body        => { text => 'Persistent Topic' },
    );

    my $publish_cv = AnyEvent->condvar;
    my $publish_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        $publish_cv->send if $parsed->type eq 'OK' && $parsed->accepted;
      });
      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $publish_cv->recv;
    ok $publish_ref, 'websocket client stays alive for persisted publish';

    _stop_relay_process($proc);
    undef $proc;

    $proc = _spawn_relay_process(
      port       => $port,
      store_file => $store_file,
    );
    _wait_for_relay_ready($port);

    my $response = _http_request(
      port => $port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alive%3A%23persist HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/json',
        'Connection: close',
        '',
        '',
      ),
    );

    like $response, qr/\AHTTP\/1\.[01] 200 /, 'persisted object endpoint returns HTTP 200 after restart';
    my $body = _decode_http_json_body($response);
    is $body->{state_event}{id}, $state_event->id, 'persisted state event survives relay restart';

    my @received;
    my $cv = AnyEvent->condvar;
    my $conn_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      my $phase = 'publish';
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;

        if ($phase eq 'publish' && $parsed->type eq 'OK') {
          $phase = 'query';
          my $filter = Net::Nostr::Filter->new(
            kinds => [37800],
            '#t'  => ['chat.topic'],
            '#o'  => ['chat.channel'],
            '#d'  => ['irc:live:#persist'],
          );
          $conn->send(Net::Nostr::Message->new(
            type            => 'REQ',
            subscription_id => 'persist-sub',
            filters         => [$filter],
          )->serialize);
          return;
        }

        $cv->send if $phase eq 'query' && $parsed->type eq 'EOSE';
      });

      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $cv->recv;
    ok $conn_ref, 'websocket client stays alive for persisted duplicate publish/query';

    my ($ok_msg) = grep { $_->type eq 'OK' } @received;
    ok $ok_msg, 'duplicate publish still returns OK after restart';
    ok $ok_msg->accepted, 'duplicate publish remains accepted';
    like $ok_msg->message, qr/\Aaccepted: duplicate /, 'duplicate publish is reported as a duplicate';

    my @event_msgs = grep {
      $_->type eq 'EVENT' && (($_->subscription_id || '') eq 'persist-sub')
    } @received;
    is scalar @event_msgs, 1, 'persisted replay query still returns one matching event';
    is $event_msgs[0]->event->id, $state_event->id, 'persisted replay query returns the stored event id';
  };
  my $error = $@;
  _stop_relay_process($proc) if $proc;
  die $error if $error;
};

subtest 'relay backup script copies persisted relay state for restore' => sub {
  my $tmpdir = tempdir(CLEANUP => 1);
  my $store_file = File::Spec->catfile($tmpdir, 'relay-store.json');
  my $backup_file = File::Spec->catfile($tmpdir, 'relay-store.backup.json');
  my $port = _free_port();
  my $proc = _spawn_relay_process(
    port       => $port,
    store_file => $store_file,
  );
  eval {
    _wait_for_relay_ready($port);

    my $author = Net::Nostr::Key->new;
    my $state_event = _create_overnet_event(
      key         => $author,
      kind        => 37800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => 'irc:live:#backup',
      body        => { text => 'Backed Up Topic' },
    );

    my $publish_cv = AnyEvent->condvar;
    my $publish_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        $publish_cv->send if $parsed->type eq 'OK' && $parsed->accepted;
      });
      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $publish_cv->recv;
    ok $publish_ref, 'websocket client stays alive for backup publish';

    _stop_relay_process($proc);
    undef $proc;

    my $backup = _run_relay_backup(
      source_store_file => $store_file,
      backup_file       => $backup_file,
    );
    is $backup->{exit_code}, 0, 'backup command succeeds';
    ok -f $backup_file, 'backup command writes the backup file';

    $proc = _spawn_relay_process(
      port       => $port,
      store_file => $backup_file,
    );
    _wait_for_relay_ready($port);

    my $response = _http_request(
      port => $port,
      request => join(
        "\r\n",
        'GET /.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alive%3A%23backup HTTP/1.1',
        'Host: 127.0.0.1',
        'Accept: application/json',
        'Connection: close',
        '',
        '',
      ),
    );

    like $response, qr/\AHTTP\/1\.[01] 200 /, 'restored backup object endpoint returns HTTP 200';
    my $body = _decode_http_json_body($response);
    is $body->{state_event}{id}, $state_event->id, 'restored backup serves the stored state event';

    my @received;
    my $cv = AnyEvent->condvar;
    my $conn_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      my $phase = 'publish';
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @received, $parsed;

        if ($phase eq 'publish' && $parsed->type eq 'OK') {
          $phase = 'query';
          my $filter = Net::Nostr::Filter->new(
            kinds => [37800],
            '#t'  => ['chat.topic'],
            '#o'  => ['chat.channel'],
            '#d'  => ['irc:live:#backup'],
          );
          $conn->send(Net::Nostr::Message->new(
            type            => 'REQ',
            subscription_id => 'backup-sub',
            filters         => [$filter],
          )->serialize);
          return;
        }

        $cv->send if $phase eq 'query' && $parsed->type eq 'EOSE';
      });

      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $cv->recv;
    ok $conn_ref, 'websocket client stays alive for backup restore duplicate publish/query';

    my @event_msgs = grep {
      $_->type eq 'EVENT' && (($_->subscription_id || '') eq 'backup-sub')
    } @received;
    is scalar @event_msgs, 1, 'restored backup query returns one matching event';
    is $event_msgs[0]->event->id, $state_event->id, 'restored backup query returns the stored event id';
  };
  my $error = $@;
  _stop_relay_process($proc) if $proc;
  die $error if $error;
};

subtest 'relay process supports live negentropy reconciliation with mirror-tag filters' => sub {
  my $port = _free_port();
  my $proc = _spawn_relay_process(port => $port);
  eval {
    _wait_for_relay_ready($port);

    my $author = Net::Nostr::Key->new;
    my $state_event = _create_overnet_event(
      key         => $author,
      kind        => 37800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => 'irc:live:#overnet',
      body        => { text => 'Negentropy Topic' },
    );

    my $publish_cv = AnyEvent->condvar;
    my $publish_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        $publish_cv->send if $parsed->type eq 'OK' && $parsed->accepted;
      });
      $conn->send(Net::Nostr::Message->new(type => 'EVENT', event => $state_event)->serialize);
    });
    $publish_cv->recv;
    ok $publish_ref, 'websocket client stays alive for negentropy publish';

    my $ne = Net::Nostr::Negentropy->new;
    $ne->seal;

    my $neg_cv = AnyEvent->condvar;
    my @neg_received;
    my $neg_ref = _connect_ws($port, sub {
      my ($conn) = @_;
      $conn->on(each_message => sub {
        my (undef, $msg) = @_;
        my $parsed = Net::Nostr::Message->parse($msg->body);
        push @neg_received, $parsed;
        $neg_cv->send if $parsed->type eq 'NEG-MSG';
      });

      my $filter = Net::Nostr::Filter->new(
        kinds => [37800],
        '#t'  => ['chat.topic'],
        '#o'  => ['chat.channel'],
        '#d'  => ['irc:live:#overnet'],
      );
      $conn->send(Net::Nostr::Message->new(
        type            => 'NEG-OPEN',
        subscription_id => 'neg-live',
        filter          => $filter,
        neg_msg         => $ne->initiate,
      )->serialize);
    });
    $neg_cv->recv;
    ok $neg_ref, 'websocket client stays alive for negentropy exchange';

    my ($neg_msg) = grep { $_->type eq 'NEG-MSG' } @neg_received;
    ok $neg_msg, 'relay returned NEG-MSG';
    my ($next, $have, $need) = $ne->reconcile($neg_msg->neg_msg);
    is_deeply $have, [], 'empty client has nothing the relay lacks';
    is_deeply $need, [$state_event->id], 'relay reports the matching state event as needed';
    ok !defined($next) || $next =~ /\A[0-9a-f]+\z/, 'negentropy follow-up message is hex or complete';
  };
  my $error = $@;
  _stop_relay_process($proc);
  die $error if $error;
};

done_testing;
