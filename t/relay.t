use strictures 2;

use File::Temp qw(tempdir);
use JSON       ();
use POSIX      ();
use Test2::V0;

use Net::Nostr::Event;
use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Message;
use Net::Nostr::Negentropy;
use Overnet::Relay;
use Overnet::Relay::Deploy;
use Overnet::Relay::Info;
use Overnet::Relay::ProfileContracts;
use Overnet::Relay::Store::File;
use Overnet::Relay::Sync;

my $JSON = JSON->new->utf8->canonical;

{

  package _TestSyncRelay;

  use Moo;

  no Moo;

  sub store { return {}; }

  sub accept_synced_event { return 1; }
}

{

  package _TestConn;

  use Moo;

  has sent_messages => (is => 'ro', reader => '_sent_messages', default => sub { [] });

  no Moo;

  sub send {
    my ($self, $message) = @_;
    push @{$self->{sent_messages}}, $message;
    return $self;
  }

  sub sent_messages {
    my ($self) = @_;
    return $self->{sent_messages};
  }

}

{

  package _TestWriteHandle;

  use Moo;

  has writes => (is => 'ro', default => sub { [] });

  no Moo;

  sub TIEHANDLE { return shift->new(@_); }

  sub WRITE {
    my ($self) = @_;
    my $write = shift @{$self->{writes}};
    return ref($write) eq 'CODE' ? $write->() : $write;
  }
}

subtest 'Moo constructors preserve hashref argument compatibility' => sub {
  my $relay = Overnet::Relay->new(
    {
      relay_url               => 'ws://relay.example.test',
      name                    => 'Hashref Relay',
      profile_contract_policy => 'off',
    }
  );
  ok $relay->isa('Overnet::Relay'), 'relay constructed';
  is $relay->name,         'Hashref Relay', 'relay received Overnet args';
  is $relay->relay_url,    'ws://relay.example.test', 'relay received Net::Nostr args';
  is $relay->core_version, '0.1.0',         'relay defaults still applied';

  my $deploy = Overnet::Relay::Deploy->new(
    {
      relay_url               => 'ws://deploy.example.test',
      name                    => 'Deploy Relay',
      profile_contract_policy => 'off',
    }
  );
  ok $deploy->isa('Overnet::Relay::Deploy'), 'deploy relay constructed';
  is $deploy->name, 'Deploy Relay', 'deploy relay received Overnet args';

  my $info = Overnet::Relay::Info->new({name => 'Info Relay', supported_nips => []});
  ok $info->isa('Overnet::Relay::Info'), 'relay info constructed';
  is $info->name, 'Info Relay', 'relay info received args';

  my $contracts = Overnet::Relay::ProfileContracts->new({contracts => [], policy => 'off'});
  ok $contracts->isa('Overnet::Relay::ProfileContracts'), 'profile contracts constructed';
  is $contracts->policy, 'off', 'profile contract policy received args';

  my $sync = Overnet::Relay::Sync->new({local_relay => _TestSyncRelay->new});
  ok $sync->isa('Overnet::Relay::Sync'), 'relay sync constructed';
  is $sync->timeout_seconds, 5, 'relay sync defaults still applied';

  my $dir   = tempdir(CLEANUP => 1);
  my $store = Overnet::Relay::Store::File->new({path => "$dir/store.json", max_events => 1});
  ok $store->isa('Overnet::Relay::Store::File'), 'file store constructed';
  is $store->path, "$dir/store.json", 'file store received path';
  is $store->max_events, 1, 'file store received Net::Nostr args';

  my $error = eval {
    Overnet::Relay::Store::File->new;
    1;
  } ? undef : $@;
  like $error, qr/path\ is\ required/mx, 'file store still requires a path';
};

subtest 'NIP-11 info includes Overnet metadata' => sub {
  my $relay = _build_relay();
  my $body  = $relay->relay_info->to_hash;

  is $body->{name}, 'Overnet Test Relay', 'relay info name';
  ok grep($_ == 77, @{$body->{supported_nips} || []}), 'supported_nips includes 77';
  ok grep($_ eq 'overnet.events.sync', @{$body->{overnet}{capabilities} || []}),
    'capabilities include overnet.events.sync';
  is $body->{overnet}{limits}{max_negentropy_sessions}, 4, 'overnet limits expose negentropy session limit';
};

subtest 'volunteer-basic applies enforced default limits matching what it advertises' => sub {
  my $relay = Overnet::Relay->new(
    relay_url               => 'ws://relay.example.test',
    profile_contract_policy => 'off',
  );
  is $relay->relay_profile, 'volunteer-basic', 'defaults to volunteer-basic profile';

  # The NIP-11 document advertises these limits, so they must actually be set
  # (and therefore enforced) rather than only appearing as advertised fallbacks.
  is $relay->max_subscriptions,  32,    'default max_subscriptions is set';
  is $relay->max_limit,          100,   'default max_limit is set';
  is $relay->default_limit,      100,   'default request limit is set';
  is $relay->max_message_length, 65536, 'default max_message_length is set';

  my $limits = $relay->relay_info->to_hash->{overnet}{limits};
  is $limits->{max_subscriptions}, $relay->max_subscriptions,
    'advertised max_subscriptions equals the enforced value';
  is $limits->{max_filter_limit}, $relay->max_limit,
    'advertised max_filter_limit equals the enforced value';
  is $limits->{max_event_bytes}, $relay->max_message_length,
    'advertised max_event_bytes equals the enforced value';
};

subtest 'operator-provided limits override the volunteer-basic defaults' => sub {
  my $relay = Overnet::Relay->new(
    relay_url               => 'ws://relay.example.test',
    profile_contract_policy => 'off',
    max_subscriptions       => 5,
    max_limit               => 20,
    max_message_length      => 1024,
  );
  is $relay->max_subscriptions,  5,    'operator max_subscriptions preserved';
  is $relay->max_limit,          20,   'operator max_limit preserved';
  is $relay->max_message_length, 1024, 'operator max_message_length preserved';
};

subtest 'volunteer-basic actually enforces the default request limit' => sub {
  my $relay = Overnet::Relay->new(
    relay_url               => 'ws://relay.example.test',
    profile_contract_policy => 'off',
  );
  $relay->_connections({1 => _TestConn->new});
  $relay->_subscriptions({1 => {}});
  $relay->_authenticated({1 => {}});
  $relay->_rate_state({});
  $relay->_neg_sessions({1 => {}});
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});

  # A REQ whose filter declares no limit must be bounded rather than returning
  # the entire store.
  my $filter = Net::Nostr::Filter->new(kinds => [7800]);
  $relay->_handle_req(1, 'sub-unbounded', $filter);
  is $filter->limit, 100, 'an unbounded filter is capped to the default limit';
};

my $author      = Net::Nostr::Key->new;
my $valid_event = _create_overnet_event(
  key         => $author,
  kind        => 7800,
  event_type  => 'chat.message',
  object_type => 'chat.channel',
  object_id   => 'irc:local:#overnet',
  body        => {text => 'hello relay'},
);

subtest 'publishes a valid Overnet event' => sub {
  my $relay = _build_relay();
  my $conn  = $relay->_connections->{1};

  $relay->_handle_event(1, $valid_event);

  my $ok = _last_message_of_type($conn, 'OK');
  ok $ok, 'received publish result';
  is $ok->event_id, $valid_event->id, 'publish result references event id';
  ok $ok->accepted, 'event accepted';
  like $ok->message, qr/\Aaccepted:/mx, 'accept result uses accepted prefix';
  is $relay->store->get_by_id($valid_event->id)->id, $valid_event->id, 'event stored in relay store';
};

my $invalid_missing_mirror = $author->create_event(
  kind => 7800,
  tags => [
    ['overnet_v',   '0.1.0'],
    ['overnet_et',  'chat.message'],
    ['overnet_ot',  'chat.channel'],
    ['overnet_oid', 'irc:local:#overnet'],
  ],
  content => $JSON->encode(
    {
      provenance => {type => 'native'},
      body       => {text => 'missing mirror tags'},
    }
  ),
);

subtest 'rejects events missing mirror tags' => sub {
  my $relay = _build_relay();
  my $conn  = $relay->_connections->{1};

  $relay->_handle_event(1, $invalid_missing_mirror);

  my $ok = _last_message_of_type($conn, 'OK');
  ok $ok,            'received rejection result';
  ok !$ok->accepted, 'event rejected';
  like $ok->message, qr/\Ainvalid:\s+Missing\ required\ v\ tag/mx, 'rejects missing mirror tags';
  ok !$relay->store->get_by_id($invalid_missing_mirror->id), 'invalid event not stored';
};

subtest 'supports canonical Overnet tag queries over REQ' => sub {
  my $relay = _build_relay();
  my $conn  = $relay->_connections->{1};
  $relay->store->store($valid_event);

  my $filter = Net::Nostr::Filter->new(
    kinds          => [7800],
    '#overnet_et'  => ['chat.message'],
    '#overnet_ot'  => ['chat.channel'],
    '#overnet_oid' => ['irc:local:#overnet'],
  );
  $relay->_handle_req(1, 'sub-overnet', $filter);

  my @messages    = map  { Net::Nostr::Message->parse($_) } @{$conn->sent_messages};
  my ($event_msg) = grep { $_->type eq 'EVENT' } @messages;
  my ($eose_msg)  = grep { $_->type eq 'EOSE' } @messages;

  ok $event_msg, 'query returned an EVENT frame';
  is $event_msg->subscription_id, 'sub-overnet',    'subscription id matches';
  is $event_msg->event->id,       $valid_event->id, 'query returned the published event';
  ok $eose_msg, 'query returned EOSE';
  is $eose_msg->subscription_id, 'sub-overnet', 'EOSE subscription id matches';
};

my $state_event = _create_overnet_event(
  key         => $author,
  kind        => 37800,
  event_type  => 'chat.topic',
  object_type => 'chat.channel',
  object_id   => 'irc:local:#overnet',
  body        => {text => 'Relay Topic'},
);

subtest 'object-read endpoint returns current state view' => sub {
  my $relay = _build_relay();
  $relay->store->store($state_event);

  my $response =
    $relay->_handle_object_http_request('GET',
    '/.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alocal%3A%23overnet',
    );

  like $response, qr/\AHTTP\/1\.[01]\ 200\ /mx, 'returns HTTP 200';
  my $body = _decode_http_json_body($response);
  is $body->{object_type}, 'chat.channel',       'object type matches';
  is $body->{object_id},   'irc:local:#overnet', 'object id matches';
  ok !$body->{removed}, 'object is not removed';
  is $body->{state_event}{id}, $state_event->id, 'returns latest state event';
  is $body->{removal_event},   undef,            'no removal event present';
};

subtest 'supports negentropy reconciliation with mirror-tag filters' => sub {
  my $relay = _build_relay();
  my $conn  = $relay->_connections->{1};
  $relay->store->store($state_event);

  my $ne = Net::Nostr::Negentropy->new;
  $ne->seal;

  my $filter = Net::Nostr::Filter->new(
    kinds => [37800],
    '#t'  => ['chat.topic'],
    '#o'  => ['chat.channel'],
    '#d'  => ['irc:local:#overnet'],
  );

  my $msg = Net::Nostr::Message->new(
    type            => 'NEG-OPEN',
    subscription_id => 'neg-overnet',
    filter          => $filter,
    neg_msg         => $ne->initiate,
  );
  $relay->_handle_neg_open(1, $msg);

  my $neg_msg = _last_message_of_type($conn, 'NEG-MSG');
  ok $neg_msg, 'received negentropy response';

  my ($next, $have, $need) = $ne->reconcile($neg_msg->neg_msg);
  is $have, [],                 'empty client has nothing the relay lacks';
  is $need, [$state_event->id], 'relay reports the state event as needed';
};

subtest 'HTTP response writes fail on zero-byte syswrite' => sub {
  tie *WRITE_FAILS, '_TestWriteHandle', writes => [0];

  my $error = eval {
    Overnet::Relay::_write_all(\*WRITE_FAILS, 'HTTP/1.1 200 OK');
    1;
  } ? undef : $@;

  like $error, qr/Failed\ to\ write\ relay\ response/mx, 'zero-byte write is fatal';
};

subtest 'constructor rejects malformed arguments' => sub {
  like dies { Overnet::Relay->new('odd-argument') },
    qr/constructor\ arguments\ must\ be\ a\ hash\ or\ hash\ reference/mx,
    'odd argument lists are rejected';
  like dies { Overnet::Relay->new(relay_url => 'ws://x', service_policies => 'nope') },
    qr/service_policies\ must\ be\ an\ object/mx, 'non-hash service policies are rejected';
  like dies {
    Overnet::Relay->new(relay_url => 'ws://x', service_policies => {publish => 'bogus'})
  }, qr/Invalid\ service_policies\ value\ for\ publish/mx,
    'unknown service policy values are rejected';
};

subtest 'constructor normalizes operator-supplied metadata' => sub {
  my $extra_nips = Overnet::Relay->new(
    relay_url               => 'ws://x',
    profile_contract_policy => 'off',
    supported_nips          => [77, 99],
  );
  ok grep({ $_ == 99 } @{$extra_nips->supported_nips}), 'operator NIPs are merged in';
  ok grep({ $_ == 1 } @{$extra_nips->supported_nips}),  'default NIPs are kept';

  my $custom_profile = Overnet::Relay->new(
    relay_url               => 'ws://x',
    profile_contract_policy => 'off',
    relay_profile           => 'custom-profile',
    pricing_url             => 'https://pricing.example.test',
  );
  is $custom_profile->max_subscriptions, undef,
    'non-volunteer profiles do not receive volunteer-basic limit defaults';
  my $overnet_info = $custom_profile->relay_info->to_hash->{overnet};
  is $overnet_info->{relay_profile}, 'custom-profile', 'custom profile is advertised';
  is $overnet_info->{pricing_url}, 'https://pricing.example.test', 'pricing_url is advertised';
};

subtest 'publish enforces configured event limits' => sub {
  my $long_content = _build_relay(max_content_length => 16);
  my $long_event   = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'this content is longer than sixteen bytes'},
  );
  $long_content->_handle_event(1, $long_event);
  like _last_message_of_type($long_content->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ content\ too\ long/mx, 'oversized content is rejected';

  my $tag_limited = _build_relay(max_event_tags => 4);
  $tag_limited->_handle_event(1, $valid_event);
  like _last_message_of_type($tag_limited->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ too\ many\ tags/mx, 'events with too many tags are rejected';

  my %stale_args = (
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'timing'},
  );

  my $lower_bound = _build_relay(created_at_lower_limit => 60);
  $lower_bound->_handle_event(1, _create_overnet_event(%stale_args, created_at => time() - 3_600));
  like _last_message_of_type($lower_bound->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ event\ too\ old/mx, 'events below the created_at lower limit are rejected';

  my $upper_bound = _build_relay(created_at_upper_limit => 60);
  $upper_bound->_handle_event(1, _create_overnet_event(%stale_args, created_at => time() + 3_600));
  like _last_message_of_type($upper_bound->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ event\ too\ far\ in\ the\ future/mx,
    'events beyond the created_at upper limit are rejected';

  my $expiring = _build_relay();
  $expiring->_handle_event(
    1,
    _create_overnet_event(%stale_args, extra_tags => [['expiration', time() - 100]]),
  );
  like _last_message_of_type($expiring->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ event\ has\ expired/mx, 'expired events are rejected';
};

subtest 'operator publish policies shape rejection outcomes' => sub {
  my %policy_case = (
    'unauthorized: operator says no' => qr/\Aunauthorized:\ operator\ says\ no\z/mx,
    'weird free-form denial'         => qr/\Apolicy_denied:\ weird\ free-form\ denial\z/mx,
  );

  for my $reply (sort keys %policy_case) {
    my $relay = _build_relay(on_event => sub { return (0, $reply) });
    $relay->_handle_event(1, $valid_event);
    my $ok = _last_message_of_type($relay->_connections->{1}, 'OK');
    ok !$ok->accepted, 'policy-denied event is rejected';
    like $ok->message, $policy_case{$reply}, 'denial message is normalized correctly';
  }

  my $silent = _build_relay(on_event => sub { return 0 });
  $silent->_handle_event(1, $valid_event);
  like _last_message_of_type($silent->_connections->{1}, 'OK')->message,
    qr/\Apolicy_denied:\ rejected\ by\ policy\z/mx, 'silent denial uses the default detail';

  my $ref_denial = _build_relay(on_event => sub { return (0, {}) });
  $ref_denial->_handle_event(1, $valid_event);
  like _last_message_of_type($ref_denial->_connections->{1}, 'OK')->message,
    qr/\Apolicy_denied:\ rejected\ by\ policy\z/mx, 'non-string denial uses the default detail';

  my $approving = _build_relay(on_event => sub { return 1 });
  $approving->_handle_event(1, $valid_event);
  ok _last_message_of_type($approving->_connections->{1}, 'OK')->accepted,
    'an approving policy leaves the event accepted';
};

subtest 'publish rate limiting rejects exhausted connections' => sub {
  my $relay = _build_relay(event_rate_limit => '1/60');
  $relay->_rate_state(
    {
      1 => {
        last_refill    => time(),
        refill_seconds => 60,
        max_tokens     => 1,
        tokens         => 0,
      },
    }
  );

  $relay->_handle_event(1, $valid_event);
  my $ok = _last_message_of_type($relay->_connections->{1}, 'OK');
  ok !$ok->accepted, 'rate-limited event is rejected';
  is $ok->message, 'unavailable: rate limited', 'rate limit uses the unavailable prefix';
};

subtest 'publish enforces proof-of-work requirements' => sub {
  my %pow_args = (
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
  );

  my $relay = _build_relay(min_pow_difficulty => 4);

  $relay->_handle_event(1, _create_overnet_event(%pow_args, body => {text => 'no nonce'}));
  like _last_message_of_type($relay->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ proof-of-work\ commitment\ below\ required\ 4/mx,
    'events without a nonce commitment are rejected';

  my ($weak_event, $strong_event);
  for my $nonce (0 .. 5_000) {
    my $candidate = _create_overnet_event(
      %pow_args,
      body       => {text => "pow attempt $nonce"},
      extra_tags => [['nonce', $nonce, 4]],
    );
    if (!defined($weak_event) && $candidate->difficulty < 4) {
      $weak_event = $candidate;
    }
    if (!defined($strong_event) && $candidate->difficulty >= 4) {
      $strong_event = $candidate;
    }
    last if defined($weak_event) && defined($strong_event);
  }

  $relay->_handle_event(1, $weak_event);
  like _last_message_of_type($relay->_connections->{1}, 'OK')->message,
    qr/\Ainvalid:\ insufficient\ proof\ of\ work\ \(need\ 4\ bits\)/mx,
    'committed but unmet difficulty is rejected';

  $relay->_handle_event(1, $strong_event);
  ok _last_message_of_type($relay->_connections->{1}, 'OK')->accepted,
    'sufficient proof of work is accepted';
};

subtest 'protected events require author authentication' => sub {
  my $protected = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'protected'},
    extra_tags  => [['-']],
  );

  my $unauthenticated = _build_relay();
  $unauthenticated->_handle_event(1, $protected);
  my $rejected = _last_message_of_type($unauthenticated->_connections->{1}, 'OK');
  ok !$rejected->accepted, 'protected publish without auth is rejected';
  is $rejected->message, 'unauthorized: protected event requires author authentication',
    'protected rejection explains the auth requirement';

  my $authenticated = _build_relay();
  $authenticated->_authenticated({1 => {$author->pubkey_hex => 1}});
  $authenticated->_handle_event(1, $protected);
  ok _last_message_of_type($authenticated->_connections->{1}, 'OK')->accepted,
    'protected publish from an authenticated author is accepted';

  my $synced = _build_relay();
  is $synced->accept_synced_event($protected)->{accepted}, 1,
    'sync ingestion skips the author auth requirement';
};

subtest 'duplicate events are acknowledged without re-storing' => sub {
  my $relay = _build_relay();
  $relay->_handle_event(1, $valid_event);
  $relay->_handle_event(1, $valid_event);
  my $ok = _last_message_of_type($relay->_connections->{1}, 'OK');
  ok $ok->accepted, 'duplicate publish is still accepted';
  is $ok->message, 'accepted: duplicate event already stored', 'duplicate outcome is reported';
};

subtest 'addressable state events keep only the newest version' => sub {
  my %state_args = (
    key         => $author,
    kind        => 37800,
    event_type  => 'chat.topic',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#conflict',
  );
  my $older = _create_overnet_event(%state_args, body => {text => 'old'}, created_at => 1_700_000_000);
  my $newer = _create_overnet_event(%state_args, body => {text => 'new'}, created_at => 1_700_000_100);
  my $stale = _create_overnet_event(%state_args, body => {text => 'mid'}, created_at => 1_700_000_050);

  my $relay = _build_relay();
  is $relay->accept_synced_event($older)->{stored}, 1, 'first state version is stored';
  is $relay->accept_synced_event($newer)->{stored}, 1, 'newer state version replaces it';
  ok !$relay->store->get_by_id($older->id), 'older state version is deleted';

  my $stale_result = $relay->accept_synced_event($stale);
  is $stale_result->{accepted}, 1, 'stale state version is still acknowledged';
  is $stale_result->{stored},   0, 'stale state version is not stored';
  is $stale_result->{message}, 'accepted: newer addressable event already stored',
    'stale outcome names the conflict';

  my %tie_args = (%state_args, created_at => 1_700_000_200);
  my $tie_a    = _create_overnet_event(%tie_args, body => {text => 'tie a'});
  my $tie_b    = _create_overnet_event(%tie_args, body => {text => 'tie b'});
  my ($tie_low, $tie_high) = sort { $a->id cmp $b->id } ($tie_a, $tie_b);

  is $relay->accept_synced_event($tie_high)->{stored}, 1, 'first tied version is stored';
  is $relay->accept_synced_event($tie_low)->{stored},  1,
    'the lexically lower event id wins a created_at tie';
  is $relay->accept_synced_event($tie_high)->{message},
    'accepted: newer addressable event already stored',
    'the lexically higher event id loses a created_at tie';
};

subtest 'ephemeral and replaceable handling stays available to generic events' => sub {
  # No recognized Overnet kind is ephemeral or replaceable, so the full
  # publish path cannot reach these branches; exercise the helpers directly
  # with generic Nostr events the way a future kind extension would.
  my $relay = _build_relay();

  my $ephemeral = $author->create_event(kind => 20_001, tags => [], content => 'e');
  my $broadcast = $relay->_early_acceptance_result($ephemeral, {broadcast => 1});
  is $broadcast->{accepted}, 1, 'ephemeral events are accepted';
  is $broadcast->{stored},   0, 'ephemeral events are not stored';
  is $broadcast->{message}, 'accepted: ephemeral event broadcast', 'ephemeral outcome is reported';
  my $quiet = $relay->_early_acceptance_result($ephemeral, {broadcast => 0});
  is $quiet->{message}, 'accepted: ephemeral event broadcast', 'non-broadcast ingest still accepts';
  is $relay->_early_acceptance_result($valid_event, {broadcast => 1}), undef,
    'regular unseen events take the normal path';

  my $old_profile = $author->create_event(kind => 0, tags => [], content => '{"name":"old"}',
    created_at => 1_700_000_000);
  my $new_profile = $author->create_event(kind => 0, tags => [], content => '{"name":"new"}',
    created_at => 1_700_000_100);

  is $relay->_replaceable_conflict_message($valid_event), undef,
    'non-replaceable events have no replaceable conflicts';
  is $relay->_replaceable_conflict_message($old_profile), undef,
    'a replaceable event with no stored version has no conflict';
  $relay->store->store($old_profile);
  is $relay->_replaceable_conflict_message($new_profile), undef,
    'a newer replaceable event displaces the stored version';
  ok !$relay->store->get_by_id($old_profile->id), 'the older replaceable version is deleted';
  $relay->store->store($new_profile);
  is $relay->_replaceable_conflict_message($old_profile),
    'accepted: newer replaceable event already stored',
    'an older replaceable event reports the stored newer version';
};

subtest 'REQ limits bound filters and subscriptions' => sub {
  my $filter = sub { Net::Nostr::Filter->new(kinds => [7800]) };

  my $few_filters = _build_relay(max_filters => 1);
  $few_filters->_handle_req(1, 'sub-many', $filter->(), $filter->());
  my $closed = _last_message_of_type($few_filters->_connections->{1}, 'CLOSED');
  ok $closed, 'too many filters closes the subscription request';
  is $closed->message, 'unavailable: too many filters', 'filter limit outcome is reported';

  my $few_subs = _build_relay(max_subscriptions => 1);
  $few_subs->_handle_req(1, 'sub-first', $filter->());
  $few_subs->_handle_req(1, 'sub-second', $filter->());
  my $sub_closed = _last_message_of_type($few_subs->_connections->{1}, 'CLOSED');
  ok $sub_closed, 'exceeding max subscriptions closes the request';
  is $sub_closed->message, 'unavailable: too many subscriptions',
    'subscription limit outcome is reported';

  my $replaced_filter = $filter->();
  $few_subs->_handle_req(1, 'sub-first', $replaced_filter);
  is $few_subs->_subscriptions->{1}{'sub-first'}, [$replaced_filter],
    're-issuing an existing subscription id replaces its filters';

  my $capped = _build_relay(max_limit => 10);
  my $greedy = Net::Nostr::Filter->new(kinds => [7800], limit => 500);
  $capped->_handle_req(1, 'sub-capped', $greedy);
  is $greedy->limit, 10, 'filter limits above max_limit are capped';
};

subtest 'NEG-OPEN edge conditions are reported' => sub {
  my $filter = Net::Nostr::Filter->new(kinds => [7800]);

  my $exhausted = _build_relay(max_negentropy_sessions => 0);
  my $ne        = Net::Nostr::Negentropy->new;
  $ne->seal;
  $exhausted->_handle_neg_open(
    1,
    Net::Nostr::Message->new(
      type            => 'NEG-OPEN',
      subscription_id => 'neg-full',
      filter          => $filter,
      neg_msg         => $ne->initiate,
    )
  );
  my $err = _last_message_of_type($exhausted->_connections->{1}, 'NEG-ERR');
  ok $err, 'session limit produces NEG-ERR';
  is $err->message, 'unavailable: too many negentropy sessions', 'session limit reason is reported';

  my $relay = _build_relay();
  $relay->_handle_neg_open(
    1,
    Net::Nostr::Message->new(
      type            => 'NEG-OPEN',
      subscription_id => 'neg-bad',
      filter          => $filter,
      neg_msg         => 'ff',
    )
  );
  my $invalid = _last_message_of_type($relay->_connections->{1}, 'NEG-ERR');
  ok $invalid, 'malformed negentropy frames produce NEG-ERR';
  like $invalid->message, qr/\Ainvalid:/mx, 'malformed frame reason uses the invalid prefix';
};

subtest 'removal validation context is assembled from stored events' => sub {
  my %removal_args = (
    key         => $author,
    kind        => 7801,
    event_type  => 'core.removal',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {},
  );

  my $relay  = _build_relay();
  my $target = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'to be removed'},
  );
  is $relay->accept_synced_event($target)->{stored}, 1, 'removal target is stored';

  my $delegated_removal = _create_overnet_event(
    %removal_args,
    extra_tags => [
      ['e',                $target->id],
      ['e',                'f' x 64],
      ['overnet_delegate', $target->id],
      ['-'],
    ],
  );
  my $result = $relay->accept_synced_event($delegated_removal);
  ok defined($result->{message}), 'delegated removal produces a validation outcome';

  my $dangling_removal = _create_overnet_event(
    %removal_args,
    extra_tags => [
      ['e',                'a' x 64],
      ['overnet_delegate', 'b' x 64],
    ],
  );
  like $relay->accept_synced_event($dangling_removal)->{message},
    qr/\Ainvalid:.*target\ event\ context/mxs,
    'a removal without stored context is rejected for missing context';
};

subtest 'mirror tag divergence is rejected' => sub {
  my %message_args = (
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
  );

  my $relay = _build_relay();

  my $duplicated = _create_overnet_event(
    %message_args,
    body       => {text => 'two v tags'},
    extra_tags => [['v', '0.1.0']],
  );
  like $relay->accept_synced_event($duplicated)->{message},
    qr/Duplicate\ v\ tag/mx, 'duplicate mirror tags are rejected';

  my $mismatched = $author->create_event(
    kind => 7800,
    tags => [
      ['overnet_v',   '0.1.0'],
      ['overnet_et',  'chat.message'],
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:local:#overnet'],
      ['v',           '0.2.0'],
      ['t',           'chat.message'],
      ['o',           'chat.channel'],
      ['d',           'irc:local:#overnet'],
    ],
    content => $JSON->encode({provenance => {type => 'native'}, body => {text => 'diverged'}}),
  );
  like $relay->accept_synced_event($mismatched)->{message},
    qr/v\ tag\ must\ match/mx, 'diverged mirror tags are rejected';
};

subtest 'object read endpoint validates requests' => sub {
  my $relay = _build_relay();

  like $relay->_handle_object_http_request('POST', '/.well-known/overnet/v1/object?type=a&id=b'),
    qr/\AHTTP\/1\.1\ 405\ /mx, 'non-GET object requests are rejected';

  for my $bad_path (
    '/.well-known/overnet/v1/object',
    '/.well-known/overnet/v1/object?type=chat.channel',
    '/.well-known/overnet/v1/object?id=irc%3Alocal%3A%23overnet',
    '/.well-known/overnet/v1/object?type=&id=x',
    '/.well-known/overnet/v1/object?type&id=x',
    '/.well-known/overnet/v1/object?&type=a',
  ) {
    like $relay->_handle_object_http_request('GET', $bad_path),
      qr/\AHTTP\/1\.1\ 400\ /mx, "missing object parameters are rejected: $bad_path";
  }

  like $relay->_handle_object_http_request('GET',
    '/.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alocal%3A%23missing'),
    qr/\AHTTP\/1\.1\ 404\ /mx, 'unknown objects return 404';
};

subtest 'object read endpoint reports removal state' => sub {
  my %view_args = (
    key         => $author,
    object_type => 'chat.channel',
    body        => {},
  );
  my $view = sub {
    my ($relay, $object_id) = @_;
    my $response = $relay->_handle_object_http_request('GET',
      "/.well-known/overnet/v1/object?type=chat.channel&id=$object_id");
    like $response, qr/\AHTTP\/1\.1\ 200\ /mx, "object view for $object_id returns 200";
    return _decode_http_json_body($response);
  };

  my $relay = _build_relay();

  # Removal-only object: the store never validates, so seed it directly.
  $relay->store->store(
    _create_overnet_event(
      %view_args,
      kind       => 7801,
      event_type => 'core.removal',
      object_id  => 'obj:removed-only',
      created_at => 1_700_000_100,
    )
  );
  my $removed_only = $view->($relay, 'obj:removed-only');
  ok $removed_only->{removed}, 'a removal without state reads as removed';
  is $removed_only->{state_event}, undef, 'no state event is returned';
  ok $removed_only->{removal_event}, 'the removal event is returned';

  # State followed by newer removal: removed.
  $relay->store->store(
    _create_overnet_event(
      %view_args,
      kind       => 37800,
      event_type => 'chat.topic',
      object_id  => 'obj:then-removed',
      created_at => 1_700_000_000,
    )
  );
  $relay->store->store(
    _create_overnet_event(
      %view_args,
      kind       => 7801,
      event_type => 'core.removal',
      object_id  => 'obj:then-removed',
      created_at => 1_700_000_100,
    )
  );
  ok $view->($relay, 'obj:then-removed')->{removed}, 'a newer removal marks the object removed';

  # Removal followed by newer state: restored.
  $relay->store->store(
    _create_overnet_event(
      %view_args,
      kind       => 7801,
      event_type => 'core.removal',
      object_id  => 'obj:restored',
      created_at => 1_700_000_000,
    )
  );
  $relay->store->store(
    _create_overnet_event(
      %view_args,
      kind       => 37800,
      event_type => 'chat.topic',
      object_id  => 'obj:restored',
      created_at => 1_700_000_100,
    )
  );
  my $restored = $view->($relay, 'obj:restored');
  ok !$restored->{removed}, 'a newer state event restores the object';
  ok $restored->{state_event},   'the state event is returned';
  ok $restored->{removal_event}, 'the older removal event is still disclosed';
};

subtest 'base Nostr validation failures are rejected before Overnet checks' => sub {
  my $tampered_hash = $valid_event->to_hash;
  $tampered_hash->{sig} = 'ab' x 64;
  my $tampered = Net::Nostr::Event->from_wire($tampered_hash);

  my $relay = _build_relay();
  $relay->_handle_event(1, $tampered);
  my $ok = _last_message_of_type($relay->_connections->{1}, 'OK');
  ok !$ok->accepted, 'a tampered signature is rejected';
};

subtest 'sync-style ingestion can skip broadcasting' => sub {
  my $relay  = _build_relay();
  my $result = $relay->_accept_overnet_event(
    $valid_event,
    apply_rate_limit    => 0,
    require_author_auth => 0,
    broadcast           => 0,
  );
  is $result->{stored}, 1, 'a non-broadcast ingest still stores the event';
};

subtest 'REQ limits are optional outside volunteer-basic' => sub {
  my $relay = _build_relay(
    relay_profile     => 'custom-profile',
    max_filters       => undef,
    max_limit         => undef,
    max_subscriptions => undef,
  );
  my $filter = Net::Nostr::Filter->new(kinds => [7800]);
  $relay->_handle_req(1, 'sub-unbounded', $filter);
  is $filter->limit, undef, 'no limit is imposed when none is configured';
  ok((grep { Net::Nostr::Message->parse($_)->type eq 'EOSE' }
      @{$relay->_connections->{1}->sent_messages}),
    'the unbounded REQ still completes with EOSE');
};

subtest 'removal context lookups tolerate absent delegation tags' => sub {
  my $relay   = _build_relay();
  my $removal = _create_overnet_event(
    key         => $author,
    kind        => 7801,
    event_type  => 'core.removal',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {},
    extra_tags  => [['e', 'a' x 64]],
  );
  like $relay->accept_synced_event($removal)->{message},
    qr/\Ainvalid:/mx, 'a delegate-free removal still reports its validation outcome';
};

subtest 'mirror tag helper reports each divergence' => sub {
  # The core validator rejects these shapes first on the publish path, so the
  # relay-side defensive helper is exercised directly.
  my $diverged = $author->create_event(
    kind => 7800,
    tags => [
      ['overnet_v',   '0.1.0'],
      ['overnet_et',  'chat.message'],
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:local:#overnet'],
      ['v',           '0.1.0'],
      ['v',           '0.2.0'],
      ['o',           'chat.other'],
      ['d',           'irc:local:#overnet'],
      ['bad-tag'],
    ],
    content => '{}',
  );

  my $relay  = _build_relay();
  my @errors = $relay->_mirror_tag_errors($diverged);
  is \@errors,
    [
    'Duplicate v tag',
    'Missing required t tag',
    'o tag must match overnet_ot',
    ],
    'duplicate, missing, and diverged mirror tags are each reported';
};

subtest 'outcome message normalization keeps valid prefixes' => sub {
  is(
    Overnet::Relay::_normalize_outcome_message('not_found: gone', 'policy_denied', 'detail'),
    'not_found: gone',
    'recognized outcome prefixes pass through',
  );
  is(
    Overnet::Relay::_normalize_outcome_message('surprise: gone', 'policy_denied', 'detail'),
    'policy_denied: surprise: gone',
    'unrecognized prefixes are wrapped with the default',
  );
  is(
    Overnet::Relay::_normalize_outcome_message(undef, 'policy_denied', undef),
    'policy_denied: ',
    'a missing message and detail fall back to the bare prefix',
  );
};

subtest 'first tag values skip malformed and repeated tags' => sub {
  my %values = Overnet::Relay::_first_tag_values([['solo'], ['e', 'first'], ['e', 'second'], []]);
  is \%values, {e => 'first'}, 'only well-formed first occurrences are kept';
  is {Overnet::Relay::_first_tag_values(undef)}, {}, 'missing tag lists decode to nothing';
};

subtest 'HTTP response writes retry on EINTR and fail on errors' => sub {
  my $payload = 'HTTP/1.1 200 OK';

  tie *WRITE_EINTR, '_TestWriteHandle',
    writes => [sub { $! = POSIX::EINTR(); return; }, length $payload];    ## no critic (RequireLocalizedPunctuationVars)
  is(Overnet::Relay::_write_all(\*WRITE_EINTR, $payload), length($payload),
    'interrupted writes are retried to completion');

  tie *WRITE_EPIPE, '_TestWriteHandle',
    writes => [sub { $! = POSIX::EPIPE(); return; }];    ## no critic (RequireLocalizedPunctuationVars)
  like dies { Overnet::Relay::_write_all(\*WRITE_EPIPE, $payload) },
    qr/Failed\ to\ write\ relay\ response/mx, 'non-retryable write errors are fatal';
};

subtest 'finishing an HTTP exchange reports close failures' => sub {
  my $relay = _build_relay();

  # close() on a command pipe reports the child exit status, so a failing
  # child makes the close fail without any I/O warnings.
  $relay->_conn_count_by_ip({'127.0.0.1' => 1});
  open my $fh, '|-', $^X, '-e', 'exit 1' or die "spawn failing child: $!";
  is $relay->_finish_http_request($fh, '127.0.0.1', q{}), 0,
    'a failed close is reported to the caller';
};

done_testing;

sub _build_relay {
  my (%overrides) = @_;
  my $relay = Overnet::Relay->new(
    name                    => 'Overnet Test Relay',
    description             => 'Test relay for Overnet integration coverage',
    software                => 'https://example.invalid/overnet-relay',
    version                 => '0.1.0-test',
    max_filters             => 8,
    max_limit               => 100,
    max_subscriptions       => 8,
    max_negentropy_sessions => 4,
    max_message_length      => 65536,
    max_content_length      => 32768,
    %overrides,
  );

  $relay->_connections({1 => _TestConn->new});
  $relay->_subscriptions({1 => {}});
  $relay->_authenticated({1 => {}});
  $relay->_rate_state({});
  $relay->_neg_sessions({1 => {}});
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});

  return $relay;
}

sub _create_overnet_event {
  my (%args)      = @_;
  my $key         = delete $args{key};
  my $kind        = delete $args{kind};
  my $event_type  = delete $args{event_type};
  my $object_type = delete $args{object_type};
  my $object_id   = delete $args{object_id};
  my $body        = delete $args{body};
  my $extra_tags  = delete $args{extra_tags};
  my $created_at  = delete $args{created_at};

  my @tags = (
    ['overnet_v',   '0.1.0'],
    ['overnet_et',  $event_type],
    ['overnet_ot',  $object_type],
    ['overnet_oid', $object_id],
    ['v',           '0.1.0'],
    ['t',           $event_type],
    ['o',           $object_type],
    ['d',           $object_id],
    @{$extra_tags || []},
  );

  return $key->create_event(
    kind => $kind,
    tags => \@tags,
    (defined $created_at ? (created_at => $created_at) : ()),
    content => $JSON->encode(
      {
        provenance => {type => 'native'},
        body       => $body,
      }
    ),
  );
}

sub _last_message_of_type {
  my ($conn, $type) = @_;
  for my $raw (reverse @{$conn->sent_messages}) {
    my $msg = Net::Nostr::Message->parse($raw);
    return $msg if $msg->type eq $type;
  }
  return;
}

sub _decode_http_json_body {
  my ($response) = @_;
  my (undef, $body) = split /\r\n\r\n/mx, $response, 2;
  return $JSON->decode($body);
}

