use strict;
use warnings;
use Test::More;
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3 qw(open3);
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(sleep time);

use Net::Nostr::Client;
use Net::Nostr::Event;
use Net::Nostr::Key;
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;
use Overnet::Program::Permissions;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

my $authoritative_relay_script = File::Spec->catfile($FindBin::Bin, 'authoritative-nip29-relay.pl');

sub _free_port {
  require IO::Socket::INET;

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

sub _signed_text_note {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => 1,
    created_at => $args{created_at},
    content    => $args{content},
    tags       => [],
  );
  return $event->to_hash;
}

sub _signed_event {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => $args{kind},
    created_at => $args{created_at},
    content    => $args{content},
    tags       => $args{tags} || [],
  );
  return $event->to_hash;
}

sub _drain_until_notification {
  my (%args) = @_;
  my $runtime = $args{runtime};
  my $session_id = $args{session_id};
  my $timeout_ms = $args{timeout_ms} || 1_000;
  my $deadline = time() + ($timeout_ms / 1000);

  while (time() < $deadline) {
    my $notifications = $runtime->drain_runtime_notifications($session_id);
    return $notifications if @{$notifications};
    sleep 0.05;
  }

  return [];
}

subtest 'protocol and permissions expose nostr runtime methods' => sub {
  ok(
    Overnet::Program::Protocol->is_service_request_method('nostr.publish_event'),
    'protocol accepts nostr.publish_event as a service request method'
  );
  ok(
    Overnet::Program::Protocol->is_service_request_method('nostr.query_events'),
    'protocol accepts nostr.query_events as a service request method'
  );
  ok(
    Overnet::Program::Protocol->is_service_request_method('nostr.open_subscription'),
    'protocol accepts nostr.open_subscription as a service request method'
  );
  ok(
    Overnet::Program::Protocol->is_service_request_method('nostr.read_subscription_snapshot'),
    'protocol accepts nostr.read_subscription_snapshot as a service request method'
  );
  ok(
    Overnet::Program::Protocol->is_service_request_method('nostr.close_subscription'),
    'protocol accepts nostr.close_subscription as a service request method'
  );

  is(
    Overnet::Program::Permissions->required_permission_for_method('nostr.publish_event'),
    'nostr.write',
    'nostr.publish_event requires the write permission'
  );
  is(
    Overnet::Program::Permissions->required_permission_for_method('nostr.query_events'),
    'nostr.read',
    'nostr.query_events requires the read permission'
  );
  is(
    Overnet::Program::Permissions->required_permission_for_method('nostr.open_subscription'),
    'nostr.read',
    'nostr.open_subscription requires the read permission'
  );
  is(
    Overnet::Program::Permissions->required_permission_for_method('nostr.read_subscription_snapshot'),
    'nostr.read',
    'nostr.read_subscription_snapshot requires the read permission'
  );
  is(
    Overnet::Program::Permissions->required_permission_for_method('nostr.close_subscription'),
    'nostr.read',
    'nostr.close_subscription requires the read permission'
  );
};

subtest 'delegation helper validates authoritative auth events and delegation grants' => sub {
  my $authority_key = Net::Nostr::Key->new;
  my $delegate_key = Net::Nostr::Key->new;

  my $auth_event = $authority_key->create_event(
    kind       => 22242,
    created_at => 1_744_301_000,
    content    => '',
    tags       => [
      [ 'relay', 'irc://irc.example.test/overnet' ],
      [ 'challenge', 'abc123' ],
    ],
  )->to_hash;

  my $auth = Overnet::Authority::Delegation->verify_auth_event(
    challenge => 'abc123',
    scope     => 'irc://irc.example.test/overnet',
    event     => $auth_event,
  );
  ok $auth->{valid}, 'helper accepts a valid authoritative auth event';
  is $auth->{pubkey}, $authority_key->pubkey_hex, 'helper returns the authenticated pubkey';

  my $bad_auth = Overnet::Authority::Delegation->verify_auth_event(
    challenge => 'wrong',
    scope     => 'irc://irc.example.test/overnet',
    event     => $auth_event,
  );
  ok !$bad_auth->{valid}, 'helper rejects an auth event with the wrong challenge';
  like $bad_auth->{reason}, qr/challenge/i, 'helper reports a challenge mismatch';

  my $grant_event = $authority_key->create_event(
    kind       => 14142,
    created_at => 1_744_301_001,
    content    => '',
    tags       => [
      [ 'relay', 'ws://127.0.0.1:7448' ],
      [ 'server', 'irc://irc.example.test/overnet' ],
      [ 'delegate', $delegate_key->pubkey_hex ],
      [ 'session', 'session-abc' ],
      [ 'expires_at', 1_744_304_600 ],
    ],
  )->to_hash;

  my $grant = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $authority_key->pubkey_hex,
    relay_url        => 'ws://127.0.0.1:7448',
    scope            => 'irc://irc.example.test/overnet',
    delegate_pubkey  => $delegate_key->pubkey_hex,
    session_id       => 'session-abc',
    expires_at       => 1_744_304_600,
    kind             => 14142,
    event            => $grant_event,
  );
  ok $grant->{valid}, 'helper accepts a valid delegation grant';
  is $grant->{event_id}, $grant_event->{id}, 'helper returns the accepted delegation event id';

  my $bad_grant = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $authority_key->pubkey_hex,
    relay_url        => 'ws://127.0.0.1:7448',
    scope            => 'irc://irc.example.test/overnet',
    delegate_pubkey  => ('f' x 64),
    session_id       => 'session-abc',
    expires_at       => 1_744_304_600,
    kind             => 14142,
    event            => $grant_event,
  );
  ok !$bad_grant->{valid}, 'helper rejects a delegation grant for the wrong delegate pubkey';
  like $bad_grant->{reason}, qr/delegate/i, 'helper reports the delegate mismatch';
};

subtest 'nostr services publish events, seed snapshots, and queue relay-backed subscription updates' => sub {
  my $port = _free_port();
  my $relay_url = "ws://127.0.0.1:$port";
  my $relay = _spawn_authoritative_nip29_relay(
    port      => $port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $author_key = Net::Nostr::Key->new;

  my $first_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_010,
    content    => 'seeded note',
  );
  my $published = $services->dispatch_request(
    'nostr.publish_event',
    {
      relay_url => $relay_url,
      event     => $first_event,
    },
    permissions => ['nostr.write'],
    session_id  => 'session-nostr',
  );
  ok $published->{accepted}, 'nostr.publish_event accepts a signed event';
  is $published->{event_id}, $first_event->{id}, 'nostr.publish_event returns the published event id';

  my $queried = $services->dispatch_request(
    'nostr.query_events',
    {
      relay_url => $relay_url,
      filters   => [
        {
          kinds   => [1],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
      ],
      timeout_ms => 5_000,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is scalar @{$queried->{events}}, 1, 'nostr.query_events returns matching relay events';
  is $queried->{events}[0]{id}, $first_event->{id}, 'nostr.query_events returns the published event payload';

  my $opened = $services->dispatch_request(
    'nostr.open_subscription',
    {
      subscription_id => 'relay-sub-1',
      relay_url       => $relay_url,
      filters         => [
        {
          kinds   => [1],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
      ],
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is $opened->{subscription_id}, 'relay-sub-1', 'nostr.open_subscription returns the subscription id';
  is scalar @{$opened->{events}}, 1, 'nostr.open_subscription returns the seeded snapshot';
  is $opened->{events}[0]{id}, $first_event->{id}, 'seeded snapshot includes the published event';

  my $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-1',
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is scalar @{$snapshot->{events}}, 1, 'nostr.read_subscription_snapshot returns the current snapshot';
  is $snapshot->{events}[0]{id}, $first_event->{id}, 'snapshot read returns the seeded event';

  my $second_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_011,
    content    => 'propagated note',
  );
  my $relay_publish = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $second_event,
  );
  ok $relay_publish->{accepted}, 'relay accepts an out-of-band published event';

  my $notifications = _drain_until_notification(
    runtime    => $runtime,
    session_id => 'session-nostr',
    timeout_ms => 1_500,
  );
  is scalar @{$notifications}, 1, 'runtime queues one relay-backed subscription update';
  is $notifications->[0]{method}, 'runtime.subscription_event', 'relay update uses runtime.subscription_event';
  is $notifications->[0]{params}{subscription_id}, 'relay-sub-1', 'relay update records the subscription id';
  is $notifications->[0]{params}{item_type}, 'nostr.event', 'relay update records the nostr.event item type';
  is $notifications->[0]{params}{data}{id}, $second_event->{id}, 'relay update includes the new event payload';

  $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-1',
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is scalar @{$snapshot->{events}}, 2, 'snapshot reflects the newly observed relay event';

  my $refresh_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_011_5,
    content    => 'refresh-only note',
  );
  $relay_publish = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $refresh_event,
  );
  ok $relay_publish->{accepted}, 'relay accepts a refresh-only published event';

  $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-1',
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is scalar @{$snapshot->{events}}, 2, 'snapshot does not advance before an explicit refresh or notification drain';

  $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-1',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  is scalar @{$snapshot->{events}}, 3, 'snapshot refresh pulls the latest relay event immediately';
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $refresh_event->{id}) } @{$snapshot->{events}}),
    'snapshot refresh includes the newest relay event',
  );

  my $closed = $services->dispatch_request(
    'nostr.close_subscription',
    {
      subscription_id => 'relay-sub-1',
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr',
  );
  ok $closed->{closed}, 'nostr.close_subscription confirms the close';

  my $third_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_012,
    content    => 'ignored note',
  );
  $relay_publish = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $third_event,
  );
  ok $relay_publish->{accepted}, 'relay accepts a post-close published event';

  is scalar @{_drain_until_notification(
    runtime    => $runtime,
    session_id => 'session-nostr',
    timeout_ms => 300,
  )}, 0, 'closed nostr subscription queues no further relay-backed notifications';

  _stop_authoritative_nip29_relay($relay);
};

subtest 'nostr subscriptions merge multi-filter relay snapshots and refreshes' => sub {
  my $port = _free_port();
  my $relay_url = "ws://127.0.0.1:$port";
  my $relay = _spawn_authoritative_nip29_relay(
    port      => $port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $author_key = Net::Nostr::Key->new;

  my $kind1_event = _signed_event(
    key        => $author_key,
    kind       => 1,
    created_at => 1_744_301_020,
    content    => 'kind-1',
  );
  my $kind2_event = _signed_event(
    key        => $author_key,
    kind       => 2,
    created_at => 1_744_301_021,
    content    => 'kind-2',
  );

  for my $event ($kind1_event, $kind2_event) {
    my $published = $services->dispatch_request(
      'nostr.publish_event',
      {
        relay_url => $relay_url,
        event     => $event,
      },
      permissions => ['nostr.write'],
      session_id  => 'session-nostr-multi',
    );
    ok $published->{accepted}, 'relay accepts a multi-filter seed event';
  }

  my $opened = $services->dispatch_request(
    'nostr.open_subscription',
    {
      subscription_id => 'relay-sub-multi',
      relay_url       => $relay_url,
      filters         => [
        {
          kinds   => [1],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
        {
          kinds   => [2],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
      ],
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-multi',
  );
  is $opened->{subscription_id}, 'relay-sub-multi', 'multi-filter subscription returns the subscription id';
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $kind1_event->{id}) } @{$opened->{events}}),
    'multi-filter seeded snapshot includes the first filter event',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $kind2_event->{id}) } @{$opened->{events}}),
    'multi-filter seeded snapshot includes the second filter event',
  );

  my $kind2_refresh_event = _signed_event(
    key        => $author_key,
    kind       => 2,
    created_at => 1_744_301_022,
    content    => 'kind-2-refresh',
  );
  my $relay_publish = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $kind2_refresh_event,
  );
  ok $relay_publish->{accepted}, 'relay accepts an out-of-band multi-filter refresh event';

  my $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-multi',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-multi',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $kind2_refresh_event->{id}) } @{$snapshot->{events}}),
    'multi-filter snapshot refresh includes the new second-filter event',
  );

  _stop_authoritative_nip29_relay($relay);
};

subtest 'nostr subscriptions survive live relay restart, preserve snapshots, and suppress replay duplicates' => sub {
  my $port = _free_port();
  my $relay_url = "ws://127.0.0.1:$port";
  my $relay = _spawn_authoritative_nip29_relay(
    port      => $port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $author_key = Net::Nostr::Key->new;

  my $first_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_030,
    content    => 'before-restart',
  );
  my $published = $services->dispatch_request(
    'nostr.publish_event',
    {
      relay_url => $relay_url,
      event     => $first_event,
    },
    permissions => ['nostr.write'],
    session_id  => 'session-nostr-restart',
  );
  ok $published->{accepted}, 'relay accepts the pre-restart seed event';

  my $opened = $services->dispatch_request(
    'nostr.open_subscription',
    {
      subscription_id => 'relay-sub-restart',
      relay_url       => $relay_url,
      filters         => [
        {
          kinds   => [1],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
      ],
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-restart',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$opened->{events}}),
    'seeded snapshot includes the pre-restart event',
  );

  _stop_authoritative_nip29_relay($relay);

  my $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-restart',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-restart',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$snapshot->{events}}),
    'failed refresh while the relay is down preserves the cached snapshot',
  );

  $relay = _spawn_authoritative_nip29_relay(
    port      => $port,
    relay_url => $relay_url,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-restart',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-restart',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$snapshot->{events}}),
    'empty post-restart refresh preserves the cached snapshot until relay history is replayed',
  );

  my $replayed = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $first_event,
  );
  ok $replayed->{accepted}, 'restarted relay accepts replay of the pre-restart event';

  my $second_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_031,
    content    => 'after-restart',
  );
  my $recovered = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $second_event,
  );
  ok $recovered->{accepted}, 'restarted relay accepts a new post-restart event';

  my $notifications = _drain_until_notification(
    runtime    => $runtime,
    session_id => 'session-nostr-restart',
    timeout_ms => 1_500,
  );
  is scalar @{$notifications}, 1, 'relay restart queues one notification for the truly new event';
  is $notifications->[0]{params}{data}{id}, $second_event->{id},
    'relay replay does not redeliver the already-seen event';

  $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-restart',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-restart',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$snapshot->{events}}),
    'refreshed snapshot still includes the replayed pre-restart event',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $second_event->{id}) } @{$snapshot->{events}}),
    'refreshed snapshot includes the new post-restart event',
  );

  is scalar @{$runtime->drain_runtime_notifications('session-nostr-restart')}, 0,
    'repeated refreshes after replay queue no duplicate notifications';

  my $closed = $services->dispatch_request(
    'nostr.close_subscription',
    {
      subscription_id => 'relay-sub-restart',
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-restart',
  );
  ok $closed->{closed}, 'nostr.close_subscription still closes a post-restart subscription';

  _stop_authoritative_nip29_relay($relay);
};

subtest 'new runtime subscriptions rebuild from persisted relay history after restart without duplicate notifications' => sub {
  my $tmpdir = tempdir(CLEANUP => 1);
  my $store_file = File::Spec->catfile($tmpdir, 'authoritative-relay-store.json');
  my $port = _free_port();
  my $relay_url = "ws://127.0.0.1:$port";
  my $relay = _spawn_authoritative_nip29_relay(
    port       => $port,
    relay_url  => $relay_url,
    store_file => $store_file,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $author_key = Net::Nostr::Key->new;

  my $first_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_040,
    content    => 'persisted-before-restart',
  );
  my $published = $services->dispatch_request(
    'nostr.publish_event',
    {
      relay_url => $relay_url,
      event     => $first_event,
    },
    permissions => ['nostr.write'],
    session_id  => 'session-nostr-persist-write',
  );
  ok $published->{accepted}, 'relay accepts the persisted pre-restart seed event';

  _stop_authoritative_nip29_relay($relay);

  $relay = _spawn_authoritative_nip29_relay(
    port       => $port,
    relay_url  => $relay_url,
    store_file => $store_file,
  );
  _wait_for_authoritative_nip29_relay_ready($relay_url);

  my $runtime_after = Overnet::Program::Runtime->new;
  my $services_after = Overnet::Program::Services->new(runtime => $runtime_after);

  my $opened = $services_after->dispatch_request(
    'nostr.open_subscription',
    {
      subscription_id => 'relay-sub-persist',
      relay_url       => $relay_url,
      filters         => [
        {
          kinds   => [1],
          authors => [ $author_key->pubkey_hex ],
          limit   => 10,
        },
      ],
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-persist-read',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$opened->{events}}),
    'new runtime seeded snapshot includes the persisted pre-restart event',
  );

  my $second_event = _signed_text_note(
    key        => $author_key,
    created_at => 1_744_301_041,
    content    => 'persisted-after-restart',
  );
  my $recovered = Overnet::Core::Nostr->publish_event(
    relay_url => $relay_url,
    event     => $second_event,
  );
  ok $recovered->{accepted}, 'restarted relay accepts a new post-restart event without replaying history';

  my $notifications = _drain_until_notification(
    runtime    => $runtime_after,
    session_id => 'session-nostr-persist-read',
    timeout_ms => 1_500,
  );
  is scalar @{$notifications}, 1, 'persisted recovery queues one notification for the truly new event';
  is $notifications->[0]{params}{data}{id}, $second_event->{id},
    'persisted recovery does not redeliver the already-seeded event';

  my $snapshot = $services_after->dispatch_request(
    'nostr.read_subscription_snapshot',
    {
      subscription_id => 'relay-sub-persist',
      refresh         => 1,
    },
    permissions => ['nostr.read'],
    session_id  => 'session-nostr-persist-read',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $first_event->{id}) } @{$snapshot->{events}}),
    'persisted refresh still includes the pre-restart event',
  );
  ok(
    scalar(grep { ref($_) eq 'HASH' && (($_->{id} || '') eq $second_event->{id}) } @{$snapshot->{events}}),
    'persisted refresh includes the new post-restart event',
  );

  _stop_authoritative_nip29_relay($relay);
};

done_testing;
