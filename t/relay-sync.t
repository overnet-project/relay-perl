use strictures 2;

use IO::Socket::INET;
use JSON ();
use Test2::V0;

use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Relay;
use Overnet::Relay;
use Overnet::Relay::Sync;

# This suite runs the sync helper against in-process relays so the negentropy,
# fetch, and publish plumbing is exercised inside one instrumented process.
my $JSON   = JSON->new->utf8->canonical;
my $author = Net::Nostr::Key->new;

{

  package _MethodlessRelay;

  sub new { return bless {}, shift; }
}

{

  package _FailingClient;

  sub new { return bless {}, shift; }

  sub is_connected { return 1; }

  sub disconnect { die "disconnect exploded\n"; }
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

sub _overnet_event {
  my (%args) = @_;
  my $object_id = exists $args{object_id} ? $args{object_id} : 'irc:local:#sync';
  return $author->create_event(
    kind => 7800,
    tags => [
      ['overnet_v',   '0.1.0'],
      ['overnet_et',  'chat.message'],
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', $object_id],
      ['v',           '0.1.0'],
      ['t',           'chat.message'],
      ['o',           'chat.channel'],
      ['d',           $object_id],
    ],
    content => $JSON->encode(
      {
        provenance => {type => 'native'},
        body       => {text => $args{text}},
      }
    ),
    (exists $args{created_at} ? (created_at => $args{created_at}) : ()),
  );
}

sub _started_relay {
  my (%args) = @_;
  my $port  = _free_port();
  my $relay = Overnet::Relay->new(
    relay_url               => "ws://127.0.0.1:$port",
    profile_contract_policy => 'off',
    %args,
  );
  $relay->start('127.0.0.1', $port);
  return ($relay, "ws://127.0.0.1:$port");
}

my $FILTER = sub { Net::Nostr::Filter->new(kinds => [7800]) };

subtest 'constructor validates its arguments' => sub {
  like dies { Overnet::Relay::Sync->new(bogus => 1) },
    qr/unknown\ argument\(s\):\ bogus/mx, 'unknown arguments are rejected';
  like dies { Overnet::Relay::Sync->new('odd') },
    qr/constructor\ arguments\ must\ be\ a\ hash\ or\ hash\ reference/mx,
    'odd argument lists are rejected';
  like dies { Overnet::Relay::Sync->new() },
    qr/local_relay\ or\ local_url\ is\ required/mx, 'a local side is required';
  like dies { Overnet::Relay::Sync->new(local_relay => _MethodlessRelay->new) },
    qr/local_relay\ must\ support\ store\ and\ accept_synced_event/mx,
    'incapable local relays are rejected';
  like dies { Overnet::Relay::Sync->new(local_url => q{}) },
    qr/local_relay\ or\ local_url\ is\ required/mx,
    'an empty local_url counts as no local side at all';
  like dies { Overnet::Relay::Sync->new(local_url => {}) },
    qr/local_url\ must\ be\ a\ non-empty\ string/mx, 'ref local_url is rejected';
  like dies { Overnet::Relay::Sync->new(local_url => 'ws://x', timeout_seconds => 'abc') },
    qr/timeout_seconds\ must\ be\ a\ positive\ integer/mx, 'non-numeric timeout is rejected';
  like dies { Overnet::Relay::Sync->new(local_url => 'ws://x', timeout_seconds => 0) },
    qr/timeout_seconds\ must\ be\ a\ positive\ integer/mx, 'zero timeout is rejected';
};

subtest 'sync_once validates its request arguments' => sub {
  my $sync = Overnet::Relay::Sync->new(local_url => 'ws://127.0.0.1:1');

  like dies { $sync->sync_once(bogus => 1) },
    qr/unknown\ argument\(s\):\ bogus/mx, 'unknown request arguments are rejected';
  like dies { $sync->sync_once(filter => $FILTER->()) },
    qr/remote_url\ is\ required/mx, 'remote_url is required';
  like dies { $sync->sync_once(remote_url => q{}, filter => $FILTER->()) },
    qr/remote_url\ is\ required/mx, 'an empty remote_url is rejected';
  like dies { $sync->sync_once(remote_url => 'ws://127.0.0.1:2') },
    qr/filter\ is\ required/mx, 'a filter is required';
  like dies { $sync->sync_once(remote_url => 'ws://127.0.0.1:2', filter => $author) },
    qr/filter\ is\ required/mx, 'non-filter objects are rejected';
  like dies {
    $sync->sync_once(remote_url => 'ws://127.0.0.1:2', filter => $FILTER->(), local_url => undef)
  }, qr/sync_once\ requires\ local_relay\ or\ local_url/mx,
    'overriding local_url away without a local relay is rejected';
  like dies {
    $sync->sync_once(remote_url => 'ws://127.0.0.1:2', filter => $FILTER->(), local_url => [])
  }, qr/local_url\ must\ be\ a\ non-empty\ string/mx, 'a malformed local_url override is rejected';
};

subtest 'sync_once pulls missing events into an in-process local relay' => sub {
  my ($remote, $remote_url) = _started_relay();
  my $shared  = _overnet_event(text => 'shared',  created_at => 1_700_000_000);
  my $missing = _overnet_event(text => 'missing', created_at => 1_700_000_001);
  is $remote->accept_synced_event($shared)->{stored},  1, 'remote stores the shared event';
  is $remote->accept_synced_event($missing)->{stored}, 1, 'remote stores the missing event';

  my $local = Overnet::Relay->new(
    relay_url               => 'ws://local.invalid',
    profile_contract_policy => 'off',
  );
  is $local->accept_synced_event($shared)->{stored}, 1, 'local already has the shared event';

  my $sync   = Overnet::Relay::Sync->new(local_relay => $local, timeout_seconds => 20);
  my $result = $sync->sync_once(
    remote_url => $remote_url,
    filter     => $FILTER->(),
  );

  is $result->{need_ids},    [sort $missing->id], 'negentropy reports the missing event';
  is $result->{fetched_ids}, [sort $missing->id], 'the missing event is fetched';
  is $result->{stored_ids},  [$missing->id],      'the missing event is stored locally';
  is $result->{rejected_ids},   [], 'nothing is rejected';
  is $result->{unresolved_ids}, [], 'nothing is unresolved';
  is $result->{subscription_id}, 'overnet-sync', 'the default subscription id is used';
  ok $result->{negentropy_rounds} >= 1, 'at least one negentropy round ran';
  ok $local->store->get_by_id($missing->id), 'the local relay now holds the event';

  my $noop = $sync->sync_once(
    remote_url      => $remote_url,
    filter          => $FILTER->(),
    subscription_id => 'custom-sync',
  );
  is $noop->{need_ids}, [], 'a repeated sync needs nothing';
  is $noop->{subscription_id}, 'custom-sync', 'a custom subscription id is used';
};

subtest 'sync_once through a local relay URL publishes fetched events' => sub {
  # The remote is a plain Nostr relay so it can hold an event the Overnet
  # local relay must reject.
  my $remote_port = _free_port();
  my $remote      = Net::Nostr::Relay->new(relay_url => "ws://127.0.0.1:$remote_port");
  $remote->start('127.0.0.1', $remote_port);

  my $good = _overnet_event(text => 'valid overnet event', created_at => 1_700_000_002);
  my $bad  = $author->create_event(kind => 7800, tags => [], content => 'not overnet shaped');
  $remote->inject_event($good);
  $remote->inject_event($bad);

  my ($local, $local_url) = _started_relay();
  my $seed = _overnet_event(text => 'local seed', created_at => 1_700_000_003);
  is $local->accept_synced_event($seed)->{stored}, 1, 'local relay holds a seed event';

  my $sync   = Overnet::Relay::Sync->new(local_url => $local_url, timeout_seconds => 20);
  my $result = $sync->sync_once(
    remote_url => "ws://127.0.0.1:$remote_port",
    filter     => $FILTER->(),
  );

  is $result->{need_ids}, [sort ($good->id, $bad->id)], 'both remote events are needed';
  is $result->{stored_ids},   [$good->id], 'the valid event is published and stored';
  is $result->{rejected_ids}, [$bad->id],  'the invalid event is rejected by the local relay';
  is $result->{unresolved_ids}, [], 'every needed event was fetched';
  ok $local->store->get_by_id($good->id), 'the valid event reached the local relay store';
  ok !$local->store->get_by_id($bad->id), 'the invalid event did not';
};

subtest 'remote negentropy errors abort the sync' => sub {
  my ($remote, $remote_url) = _started_relay(max_negentropy_sessions => 0);
  my $sync = Overnet::Relay::Sync->new(local_url => 'ws://unused.invalid', timeout_seconds => 20);

  like dies {
    $sync->sync_once(
      remote_url  => $remote_url,
      filter      => $FILTER->(),
      local_url   => undef,
      local_relay => undef,
    )
  }, qr/unknown\ argument\(s\)/mx, 'local overrides are not spellable as request arguments';

  my $local = Overnet::Relay->new(
    relay_url               => 'ws://local.invalid',
    profile_contract_policy => 'off',
  );
  my $relay_sync = Overnet::Relay::Sync->new(local_relay => $local, timeout_seconds => 20);
  like dies {
    $relay_sync->sync_once(remote_url => $remote_url, filter => $FILTER->())
  }, qr/remote\ negentropy\ error:/mx, 'NEG-ERR responses become sync failures';
};

subtest 'unreachable local relay URLs abort the sync' => sub {
  my $port = _free_port();
  my $sync = Overnet::Relay::Sync->new(local_url => "ws://127.0.0.1:$port", timeout_seconds => 2);
  ok dies {
    $sync->sync_once(remote_url => "ws://127.0.0.1:$port", filter => $FILTER->())
  }, 'a dead local relay URL fails the seed query';
};

subtest 'store and publish helpers classify results' => sub {
  my $local = Overnet::Relay->new(
    relay_url               => 'ws://local.invalid',
    profile_contract_policy => 'off',
  );
  my $good = _overnet_event(text => 'store me', created_at => 1_700_000_004);
  my $bad  = $author->create_event(kind => 7800, tags => [], content => 'invalid');

  my $result = Overnet::Relay::Sync::_store_fetched_events_in_relay(
    local_relay    => $local,
    requested_ids  => [sort ($good->id, $bad->id, 'f' x 64)],
    fetched_events => {
      $good->id => $good,
      $bad->id  => $bad,
    },
  );
  is $result->{stored_ids},   [$good->id], 'accepted events are reported stored';
  is $result->{rejected_ids}, [$bad->id],  'rejected events are reported rejected';

  my $duplicate = Overnet::Relay::Sync::_store_fetched_events_in_relay(
    local_relay    => $local,
    requested_ids  => [$good->id],
    fetched_events => {$good->id => $good},
  );
  is $duplicate->{stored_ids},   [], 'duplicate events are not re-reported as stored';
  is $duplicate->{rejected_ids}, [], 'duplicate events are not rejected either';

  my $sync  = Overnet::Relay::Sync->new(local_url => 'ws://127.0.0.1:1', timeout_seconds => 1);
  my $empty = $sync->_publish_fetched_events_to_url(
    local_url       => 'ws://127.0.0.1:1',
    requested_ids   => ['a' x 64],
    fetched_events  => {},
    subscription_id => 'noop-publish',
  );
  is $empty, {stored_ids => [], rejected_ids => []},
    'publishing nothing skips the local connection entirely';

  like dies {
    $sync->_publish_fetched_events_to_url(
      local_url       => 'ws://127.0.0.1:' . _free_port(),
      requested_ids   => [$good->id],
      fetched_events  => {$good->id => $good},
      subscription_id => 'dead-publish',
    )
  }, qr/./mxs, 'publishing to a dead local relay fails';

  my ($live_local, $live_local_url) = _started_relay();
  my $duplicate_event = _overnet_event(text => 'already stored', created_at => 1_700_000_005);
  is $live_local->accept_synced_event($duplicate_event)->{stored}, 1,
    'local relay already holds the duplicate event';
  my $live_sync = Overnet::Relay::Sync->new(local_url => $live_local_url, timeout_seconds => 20);
  my $dup_publish = $live_sync->_publish_fetched_events_to_url(
    local_url       => $live_local_url,
    requested_ids   => [$duplicate_event->id],
    fetched_events  => {$duplicate_event->id => $duplicate_event},
    subscription_id => 'dup-publish',
  );
  is $dup_publish, {stored_ids => [], rejected_ids => []},
    'republishing a stored event is neither stored nor rejected';
};

subtest 'sync result classification reports unresolved ids' => sub {
  my $result = Overnet::Relay::Sync::_sync_result(
    {remote_url => 'ws://remote.invalid', subscription_id => 'classify'},
    {
      need              => {'aa' => 1, 'bb' => 1, 'cc' => 1},
      fetched           => {'aa' => 1, 'bb' => 1},
      stored_ids        => ['aa'],
      rejected_ids      => ['bb'],
      negentropy_rounds => 3,
    },
  );
  is $result->{need_ids}, [qw(aa bb cc)], 'needed ids are sorted';
  is $result->{unresolved_ids}, ['cc'], 'ids neither stored nor fetched are unresolved';
  is $result->{negentropy_rounds}, 3, 'round count is preserved';
};

subtest 'filter and client helpers' => sub {
  my $limited = Net::Nostr::Filter->new(kinds => [7800], limit => 5);
  is(Overnet::Relay::Sync::_unlimited_filter($limited)->limit,
    undef, 'negentropy filters drop their limit');

  is(Overnet::Relay::Sync::_disconnect_client_quietly(_FailingClient->new),
    0, 'a failing disconnect is swallowed quietly');

  my $waiter = Overnet::Relay::Sync::_callback_waiter(
    timeout_seconds => 1,
    error_prefix    => 'unit wait',
  );
  like dies { Overnet::Relay::Sync::_recv_callback_waiter($waiter) },
    qr/unit\ wait\ timed\ out\ after\ 1\ seconds/mx, 'callback waiters time out';
};

done_testing;
