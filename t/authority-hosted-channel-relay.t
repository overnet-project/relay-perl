use strictures 2;

use Test2::V0;

use Net::Nostr::Key;
use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);

my $RELAY_URL  = 'ws://127.0.0.1:7448';
my $AUTH_SCOPE = 'irc://irc.example/localnet';
my $GRANT_KIND = 14_142;
my $GROUP_ID   = 'localnet-overnet';
my $BASE_TIME  = 1_750_000_000;

my $operator_key         = Net::Nostr::Key->new;
my $operator_session_key = Net::Nostr::Key->new;
my $attacker_key         = Net::Nostr::Key->new;
my $attacker_session_key = Net::Nostr::Key->new;
my $snapshot_key         = Net::Nostr::Key->new;

sub _relay {
  my (%args) = @_;
  return build_authoritative_relay(
    relay_url  => $RELAY_URL,
    grant_kind => $GRANT_KIND,
    %args,
  );
}

sub _authorize {
  my ($relay,    $event)  = @_;
  my ($accepted, $reason) = $relay->on_event->($event);
  return ($accepted, $reason);
}

sub _grant_event {
  my (%args)     = @_;
  my $actor_key  = $args{actor_key};
  my $expires_at = exists $args{expires_at} ? $args{expires_at} : $BASE_TIME + 3_600;
  my @tags       = (
    ['relay', exists $args{relay_url} ? $args{relay_url} : $RELAY_URL],
    (exists $args{omit_server}        ? ()               : ['server', $AUTH_SCOPE]),
    ['delegate', $args{delegate_pubkey}],
    (exists $args{omit_session} ? ()                              : ['session', 'session-1']),
    (defined $expires_at        ? (['expires_at', "$expires_at"]) : ()),
  );
  return $actor_key->create_event(
    kind       => exists $args{kind} ? $args{kind} : $GRANT_KIND,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => \@tags,
  );
}

sub _control_event {
  my (%args)      = @_;
  my $session_key = $args{session_key};
  my @tags        = (
    ['h',                 $GROUP_ID],
    ['overnet_actor',     $args{actor_pubkey}],
    ['overnet_authority', $args{authority_id}],
    ['overnet_sequence',  exists $args{sequence} ? $args{sequence} : '1'],
    @{$args{extra_tags} || []},
  );
  return $session_key->create_event(
    kind       => $args{kind},
    created_at => exists $args{created_at} ? $args{created_at} : $BASE_TIME + 10,
    content    => q{},
    tags       => \@tags,
  );
}

sub _initial_operator_grant_control {
  my (%args) = @_;
  return _control_event(
    kind         => 9_000,
    session_key  => $args{session_key},
    actor_pubkey => $args{actor_pubkey},
    authority_id => $args{authority_id},
    extra_tags   => [['p', $args{actor_pubkey}, 'irc.operator']],
    (exists $args{created_at} ? (created_at => $args{created_at}) : ()),
  );
}

sub _snapshot_event {
  my (%args) = @_;
  return $args{signer_key}->create_event(
    kind       => $args{kind},
    created_at => exists $args{created_at} ? $args{created_at} : $BASE_TIME,
    content    => q{},
    tags       => [['d', $GROUP_ID], @{$args{extra_tags} || []},],
  );
}

sub _seed_operator {
  my ($relay) = @_;
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  $relay->store->store($grant);
  my $seed = _initial_operator_grant_control(
    session_key  => $operator_session_key,
    actor_pubkey => $operator_key->pubkey_hex,
    authority_id => $grant->id,
    created_at   => $BASE_TIME + 1,
  );
  my ($accepted, $reason) = _authorize($relay, $seed);
  die "operator seed rejected: $reason" if !$accepted;
  $relay->store->store($seed);
  return $grant;
}

subtest 'constructor validates snapshot_pubkeys' => sub {
  like(
    dies { _relay(snapshot_pubkeys => 'not-an-array') },
    qr/snapshot_pubkeys\ must\ be\ an\ array\ of\ 64-char\ lowercase\ hex\ pubkeys/mx,
    'non-array snapshot_pubkeys rejected'
  );
  like(
    dies { _relay(snapshot_pubkeys => ['UPPERCASE']) },
    qr/snapshot_pubkeys\ must\ be\ an\ array\ of\ 64-char\ lowercase\ hex\ pubkeys/mx,
    'malformed snapshot pubkey rejected'
  );
  ok(_relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]), 'valid snapshot_pubkeys accepted');
};

subtest 'a verified delegation grant chain is accepted' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok $accepted, 'delegated control event accepted' or diag $reason;
};

subtest 'a control event referencing an unknown grant is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ not\ known\ to\ this\ relay/mx, 'unknown grant reason';
};

subtest 'a grant of the wrong kind is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
    kind            => 14_143,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ uses\ the\ wrong\ event\ kind/mx, 'wrong grant kind reason';
};

subtest 'an actor cannot be impersonated with a grant signed by another key' => sub {
  my $relay = _relay();
  _seed_operator($relay);

  my $forged_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($forged_grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_001,
      session_key  => $attacker_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $forged_grant->id,
      extra_tags   => [['p', $operator_key->pubkey_hex]],
    )
  );
  ok !$accepted, 'operator impersonation rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ not\ signed\ by\ the\ effective\ actor/mx,
    'grant signer mismatch reason';
};

subtest 'a grant delegating to a different session key is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $attacker_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ does\ not\ delegate\ to\ the\ event\ signer/mx,
    'delegate mismatch reason';
};

subtest 'a grant bound to a different relay URL is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
    relay_url       => 'ws://other.example:7448',
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ bound\ to\ a\ different\ relay/mx, 'relay mismatch reason';
};

subtest 'a grant missing required tags is rejected' => sub {
  my $relay = _relay();
  for my $omission (qw(omit_server omit_session)) {
    my $grant = _grant_event(
      actor_key       => $operator_key,
      delegate_pubkey => $operator_session_key->pubkey_hex,
      $omission       => 1,
    );
    $relay->store->store($grant);

    my ($accepted, $reason) = _authorize(
      $relay,
      _initial_operator_grant_control(
        session_key  => $operator_session_key,
        actor_pubkey => $operator_key->pubkey_hex,
        authority_id => $grant->id,
      )
    );
    ok !$accepted, "$omission grant rejected";
    like $reason, qr/unauthorized:\ delegation\ grant\ is\ missing\ required\ tags/mx, "$omission reason";
  }
};

subtest 'an expired grant is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
    expires_at      => $BASE_TIME + 5,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
      created_at   => $BASE_TIME + 6,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ has\ expired/mx, 'expired grant reason';
};

subtest 'a grant with a malformed expiry is rejected' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
    expires_at      => 'soon',
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'control event rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ has\ expired/mx, 'malformed expiry treated as expired';
};

subtest 'published snapshot events require a configured snapshot identity' => sub {
  my $relay = _relay();

  for my $kind (39_001, 39_002, 39_003) {
    my ($accepted, $reason) = _authorize(
      $relay,
      _snapshot_event(
        signer_key => $attacker_key,
        kind       => $kind,
        extra_tags => [['p', $attacker_key->pubkey_hex, 'irc.operator']],
      )
    );
    ok !$accepted, "kind $kind snapshot rejected without configured snapshot identity";
    like $reason, qr/unauthorized:\ group\ snapshots\ require\ an\ authoritative\ snapshot\ identity/mx,
      "kind $kind rejection reason";
  }

  my ($accepted, $reason) = _authorize(
    $relay,
    _snapshot_event(
      signer_key => $attacker_key,
      kind       => 39_000,
      extra_tags => [['closed']],
    )
  );
  ok !$accepted, 'kind 39000 without delegation tags rejected';
  like $reason, qr/unauthorized:\ missing\ overnet_actor\ tag/mx, 'kind 39000 rejection reason';
};

subtest 'a delegated 39000 metadata event bootstraps a new hosted channel' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 39_000,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
      extra_tags   => [['d', $GROUP_ID], ['name', 'overnet']],
    )
  );
  ok $accepted, 'creation-time delegated group metadata accepted' or diag $reason;
};

subtest 'a delegated 39000 metadata event requires a verified grant' => sub {
  my $relay = _relay();
  my $grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 39_000,
      session_key  => $attacker_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
      extra_tags   => [['d', $GROUP_ID], ['name', 'overnet']],
    )
  );
  ok !$accepted, 'delegated metadata with a mismatched grant rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ not\ signed\ by\ the\ effective\ actor/mx,
    'grant signer mismatch reason';
};

subtest 'a delegated 39000 metadata event requires operator role on an existing channel' => sub {
  my $relay = _relay();
  _seed_operator($relay);

  my $attacker_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($attacker_grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 39_000,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $attacker_grant->id,
      extra_tags   => [['d', $GROUP_ID], ['name', 'hijacked']],
    )
  );
  ok !$accepted, 'non-operator delegated metadata rejected';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ channel\ operator/mx, 'operator role required';
};

subtest 'an accepted delegated 39000 metadata event shapes derived state' => sub {
  my $relay = _relay();
  my $grant = _seed_operator($relay);

  my $closed_metadata = _control_event(
    kind         => 39_000,
    session_key  => $operator_session_key,
    actor_pubkey => $operator_key->pubkey_hex,
    authority_id => $grant->id,
    created_at   => $BASE_TIME + 2,
    extra_tags   => [['d', $GROUP_ID], ['closed']],
  );
  my ($metadata_accepted, $metadata_reason) = _authorize($relay, $closed_metadata);
  ok $metadata_accepted, 'operator delegated metadata accepted' or diag $metadata_reason;
  $relay->store->store($closed_metadata);

  my $joiner_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($joiner_grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_021,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $joiner_grant->id,
      created_at   => $BASE_TIME + 20,
    )
  );
  ok !$accepted, 'join without invite rejected on the closed channel';
  like $reason, qr/unauthorized:\ closed\ groups\ require\ an\ invite\ code/mx,
    'delegated metadata was folded into derived state';
};

subtest 'published snapshot events from the configured snapshot identity are accepted' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);

  my ($accepted, $reason) = _authorize(
    $relay,
    _snapshot_event(
      signer_key => $snapshot_key,
      kind       => 39_001,
      extra_tags => [['p', $operator_key->pubkey_hex, 'irc.operator']],
    )
  );
  ok $accepted, 'authoritative snapshot accepted' or diag $reason;

  my ($rejected, $reject_reason) = _authorize(
    $relay,
    _snapshot_event(
      signer_key => $attacker_key,
      kind       => 39_001,
      extra_tags => [['p', $attacker_key->pubkey_hex, 'irc.operator']],
    )
  );
  ok !$rejected, 'non-authoritative snapshot still rejected';
  like $reject_reason, qr/unauthorized:\ group\ snapshots\ require\ an\ authoritative\ snapshot\ identity/mx,
    'non-authoritative snapshot reason';
};

subtest 'a stored forged snapshot does not grant operator authority' => sub {
  my $relay = _relay();
  _seed_operator($relay);

  my $forged_snapshot = _snapshot_event(
    signer_key => $attacker_key,
    kind       => 39_001,
    created_at => $BASE_TIME + 2,
    extra_tags => [['p', $attacker_key->pubkey_hex, 'irc.operator']],
  );
  $relay->store->store($forged_snapshot);

  my $attacker_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($attacker_grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_001,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $attacker_grant->id,
      extra_tags   => [['p', $operator_key->pubkey_hex]],
    )
  );
  ok !$accepted, 'self-granted snapshot authority rejected';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ channel\ operator/mx, 'forged snapshot ignored in derived state';
};

subtest 'a snapshot from the configured identity is folded into derived state' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);

  my $snapshot = _snapshot_event(
    signer_key => $snapshot_key,
    kind       => 39_001,
    extra_tags => [['p', $operator_key->pubkey_hex, 'irc.operator']],
  );
  $relay->store->store($snapshot);

  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_002,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
      extra_tags   => [['name', 'renamed channel']],
    )
  );
  ok $accepted, 'operator role from authoritative snapshot honored' or diag $reason;
};

subtest 'concurrent session grants survive replaceable grant storage' => sub {
  my $relay = _relay();

  my $second_session_key = Net::Nostr::Key->new;
  my $grant_a            = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  my $grant_b = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $second_session_key->pubkey_hex,
  );

  # Both grants pass through the relay authorization hook, but only the
  # replaceable-storage winner stays in the store: the relay must still
  # honor the other session's grant from its retained-grant index.
  $relay->on_event->($grant_a);
  $relay->on_event->($grant_b);
  $relay->store->store($grant_b);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant_a->id,
    )
  );
  ok $accepted, 'control event under the replaced grant still accepted' or diag $reason;

  my ($accepted_b, $reason_b) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $second_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant_b->id,
    )
  );
  ok $accepted_b, 'control event under the stored grant accepted' or diag $reason_b;
};

sub _seed_banned_channel {
  my ($relay, %args) = @_;
  my @ban_tags = map { ['ban', $_] } @{$args{ban_masks} || []};
  $relay->store->store(
    _snapshot_event(
      signer_key => $snapshot_key,
      kind       => 39_000,
      extra_tags => [@ban_tags, ($args{closed} ? (['closed']) : ())],
    )
  );
  return;
}

sub _join_request {
  my (%args) = @_;
  my $grant = _grant_event(
    actor_key       => $args{actor_key},
    delegate_pubkey => $args{session_key}->pubkey_hex,
  );
  $args{relay}->store->store($grant);
  return _control_event(
    kind         => 9_021,
    session_key  => $args{session_key},
    actor_pubkey => $args{actor_key}->pubkey_hex,
    authority_id => $grant->id,
    created_at   => $BASE_TIME + 20,
    extra_tags   => $args{mask_tags},
  );
}

subtest 'a join request whose IRC mask matches an active ban is rejected' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
  _seed_banned_channel($relay, ban_masks => ['baduser!*@*']);

  my ($accepted, $reason) = _authorize(
    $relay,
    _join_request(
      relay       => $relay,
      actor_key   => $attacker_key,
      session_key => $attacker_session_key,
      mask_tags   => [['overnet_irc_mask', 'baduser!x@host.example']],
    )
  );
  ok !$accepted, 'banned mask join rejected';
  like $reason, qr/unauthorized:\ actor\ is\ banned\ from\ the\ group/mx, 'ban rejection reason';
};

subtest 'a join request omitting its IRC mask is rejected while bans are active' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
  _seed_banned_channel($relay, ban_masks => ['baduser!*@*']);

  my ($accepted, $reason) = _authorize(
    $relay,
    _join_request(
      relay       => $relay,
      actor_key   => $attacker_key,
      session_key => $attacker_session_key,
      mask_tags   => [],
    )
  );
  ok !$accepted, 'maskless join rejected when bans are active';
  like $reason, qr/unauthorized:\ join\ request\ must\ assert\ an\ IRC\ mask\ while\ bans\ are\ active/mx,
    'fail-closed rejection reason';
};

subtest 'a join request omitting its IRC mask is accepted when no bans are active' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
  _seed_banned_channel($relay, ban_masks => []);

  my ($accepted, $reason) = _authorize(
    $relay,
    _join_request(
      relay       => $relay,
      actor_key   => $attacker_key,
      session_key => $attacker_session_key,
      mask_tags   => [],
    )
  );
  ok $accepted, 'maskless join accepted on an unbanned open channel' or diag $reason;
};

subtest 'a join request with a non-matching IRC mask is accepted' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
  _seed_banned_channel($relay, ban_masks => ['baduser!*@*']);

  my ($accepted, $reason) = _authorize(
    $relay,
    _join_request(
      relay       => $relay,
      actor_key   => $attacker_key,
      session_key => $attacker_session_key,
      mask_tags   => [['overnet_irc_mask', 'gooduser!x@host.example']],
    )
  );
  ok $accepted, 'non-matching mask join accepted (relay mask bans are best-effort)' or diag $reason;
};

sub _group_state_event {
  my (%args) = @_;
  my $key = $args{key} || $operator_session_key;
  return $key->create_event(
    kind       => $args{kind},
    created_at => exists $args{created_at} ? $args{created_at} : $BASE_TIME + 5,
    content    => q{},
    tags       => [['h', $GROUP_ID], @{$args{tags} || []}],
  );
}

{

  package _UndefStore;

  sub new { return bless {}, shift; }

  sub all_events { return; }

  sub get_by_id { return; }

  sub store { return 1; }

  sub query { return []; }
}

subtest 'constructor validates relay_url, grant_kind, and store_file' => sub {
  like dies { build_authoritative_relay(grant_kind => $GRANT_KIND) },
    qr/relay_url\ is\ required/mx, 'missing relay_url rejected';
  like dies { build_authoritative_relay(relay_url => q{}, grant_kind => $GRANT_KIND) },
    qr/relay_url\ is\ required/mx, 'empty relay_url rejected';
  like dies { build_authoritative_relay(relay_url => $RELAY_URL) },
    qr/grant_kind\ must\ be\ a\ positive\ integer/mx, 'missing grant_kind rejected';
  like dies { build_authoritative_relay(relay_url => $RELAY_URL, grant_kind => '0') },
    qr/grant_kind\ must\ be\ a\ positive\ integer/mx, 'zero grant_kind rejected';
  like dies { _relay(store_file => q{}) },
    qr/store_file\ must\ be\ a\ non-empty\ string/mx, 'empty store_file rejected';
  like dies { _relay(store_file => {}) },
    qr/store_file\ must\ be\ a\ non-empty\ string/mx, 'ref store_file rejected';
};

subtest 'constructor honours explicit store and store_file arguments' => sub {
  require File::Temp;
  require Overnet::Relay::Store::File;
  my $dir = File::Temp::tempdir(CLEANUP => 1);

  my $store = Overnet::Relay::Store::File->new(path => "$dir/explicit.json");
  is _relay(store => $store)->store, exact_ref($store), 'explicit store object is used';

  my $by_path = _relay(store_file => "$dir/by-path.json");
  ok $by_path->store->isa('Overnet::Relay::Store::File'), 'store_file builds a file store';
  is $by_path->store->path, "$dir/by-path.json", 'store_file path is used';
};

subtest 'control events with malformed identity tags are rejected' => sub {
  my $relay = _relay();

  my $missing_h = $operator_session_key->create_event(
    kind       => 9_000,
    created_at => $BASE_TIME + 10,
    content    => q{},
    tags       => [
      ['overnet_actor',     $operator_key->pubkey_hex],
      ['overnet_authority', 'a' x 64],
    ],
  );
  my ($accepted, $reason) = _authorize($relay, $missing_h);
  ok !$accepted, 'control event without an h tag is rejected';
  like $reason, qr/invalid:.*require\ one\ h\ tag/mx, 'missing h tag reason';

  my $missing_authority = $operator_session_key->create_event(
    kind       => 9_000,
    created_at => $BASE_TIME + 10,
    content    => q{},
    tags       => [['h', $GROUP_ID], ['overnet_actor', $operator_key->pubkey_hex],],
  );
  ($accepted, $reason) = _authorize($relay, $missing_authority);
  ok !$accepted, 'control event without an authority tag is rejected';
  like $reason, qr/unauthorized:\ missing\ overnet_authority\ tag/mx, 'missing authority reason';

  my $self_signed = $operator_key->create_event(
    kind       => 9_000,
    created_at => $BASE_TIME + 10,
    content    => q{},
    tags       => [
      ['h',                 $GROUP_ID],
      ['overnet_actor',     $operator_key->pubkey_hex],
      ['overnet_authority', 'a' x 64],
    ],
  );
  ($accepted, $reason) = _authorize($relay, $self_signed);
  ok !$accepted, 'a control event signed by its own actor is rejected';
  like $reason, qr/unauthorized:\ authority\ signer\ must\ differ/mx, 'self-signing reason';

  my $empty_h = $operator_session_key->create_event(
    kind       => 9_000,
    created_at => $BASE_TIME + 10,
    content    => q{},
    tags       => [
      ['h',                 q{}],
      ['overnet_actor',     $operator_key->pubkey_hex],
      ['overnet_authority', 'a' x 64],
    ],
  );
  ($accepted, $reason) = _authorize($relay, $empty_h);
  ok !$accepted, 'control event with an empty h tag is rejected';
  like $reason, qr/invalid:.*require\ one\ h\ tag/mx, 'empty h tag reason';
};

subtest 'retained grants are pruned once they expire' => sub {
  my $relay = _relay();

  my $expired_grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
    expires_at      => $BASE_TIME - 100,
  );
  my ($retained_ok) = _authorize($relay, $expired_grant);
  ok $retained_ok, 'grant-kind events are accepted and retained';

  # A grant dated in the future must not advance the prune horizon.
  my $future_grant = $operator_key->create_event(
    kind       => $GRANT_KIND,
    created_at => time() + 3_600,
    content    => q{},
    tags       => [
      ['relay',      $RELAY_URL],
      ['server',     $AUTH_SCOPE],
      ['delegate',   $operator_session_key->pubkey_hex],
      ['session',    'session-future'],
      ['expires_at', time() + 7_200],
    ],
  );
  _authorize($relay, $future_grant);

  my $live_grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  _authorize($relay, $live_grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $expired_grant->id,
    )
  );
  ok !$accepted, 'a pruned grant can no longer authorize control events';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ not\ known/mx, 'pruned grant reason';

  ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $live_grant->id,
    )
  );
  ok $accepted, 'a retained live grant authorizes control events without store access' or diag $reason;
};

subtest 'tombstoned groups only accept an operator un-tombstone edit' => sub {
  my $relay    = _relay();
  my $op_grant = _seed_operator($relay);
  $relay->store->store(
    _group_state_event(
      kind       => 9_002,
      created_at => $BASE_TIME + 5,
      tags       => [['status', 'tombstoned']],
    )
  );

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_000,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $op_grant->id,
      extra_tags   => [['p', $attacker_key->pubkey_hex]],
    )
  );
  ok !$accepted, 'membership edits are rejected while tombstoned';
  like $reason, qr/unauthorized:\ group\ is\ tombstoned/mx, 'tombstoned rejection reason';

  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_002,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $op_grant->id,
      extra_tags   => [['status', 'tombstoned']],
    )
  );
  ok !$accepted, 'a metadata edit that keeps the tombstone is rejected';

  my $attacker_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($attacker_grant);
  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_002,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $attacker_grant->id,
    )
  );
  ok !$accepted, 'a non-operator cannot un-tombstone the group';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ retained\ channel\ operator/mx,
    'retained-operator rejection reason';

  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_002,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $op_grant->id,
    )
  );
  ok $accepted, 'a retained operator can un-tombstone the group' or diag $reason;
};

subtest 'a delegated 39000 metadata event is rejected for a tombstoned group' => sub {
  my $relay    = _relay();
  my $op_grant = _seed_operator($relay);
  $relay->store->store(
    _group_state_event(
      kind       => 9_002,
      created_at => $BASE_TIME + 5,
      tags       => [['status', 'tombstoned']],
    )
  );

  my ($accepted, $reason) = _authorize(
    $relay,
    $operator_session_key->create_event(
      kind       => 39_000,
      created_at => $BASE_TIME + 10,
      content    => q{},
      tags       => [
        ['d',                 $GROUP_ID],
        ['overnet_actor',     $operator_key->pubkey_hex],
        ['overnet_authority', $op_grant->id],
      ],
    )
  );
  ok !$accepted, 'delegated metadata is rejected while tombstoned';
  like $reason, qr/unauthorized:\ group\ is\ tombstoned/mx, 'tombstoned snapshot reason';
};

subtest 'a delegated 39000 metadata event requires one d tag' => sub {
  my $relay = _relay();
  my ($accepted, $reason) = _authorize(
    $relay,
    $operator_session_key->create_event(
      kind       => 39_000,
      created_at => $BASE_TIME + 10,
      content    => q{},
      tags       => [
        ['overnet_actor',     $operator_key->pubkey_hex],
        ['overnet_authority', 'a' x 64],
      ],
    )
  );
  ok !$accepted, 'a delegated 39000 event without a d tag is rejected';
  like $reason, qr/invalid:.*require\ one\ d\ tag/mx, 'missing d tag reason';

  ($accepted, $reason) = _authorize(
    $relay,
    $operator_session_key->create_event(
      kind       => 39_000,
      created_at => $BASE_TIME + 10,
      content    => q{},
      tags       => [
        ['d',                 q{}],
        ['overnet_actor',     $operator_key->pubkey_hex],
        ['overnet_authority', 'a' x 64],
      ],
    )
  );
  ok !$accepted, 'a delegated 39000 event with an empty d tag is rejected';
  like $reason, qr/invalid:.*require\ one\ d\ tag/mx, 'empty d tag reason';
};

subtest 'a grant with an empty required tag is rejected' => sub {
  my $relay = _relay();
  my $grant = $operator_key->create_event(
    kind       => $GRANT_KIND,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => [
      ['relay',      $RELAY_URL],
      ['server',     q{}],
      ['delegate',   $operator_session_key->pubkey_hex],
      ['session',    'session-1'],
      ['expires_at', $BASE_TIME + 3_600],
    ],
  );
  $relay->store->store($grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _initial_operator_grant_control(
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'a grant with an empty server tag is rejected';
  like $reason, qr/unauthorized:\ delegation\ grant\ is\ missing\ required\ tags/mx,
    'empty required tag reason';
};

subtest 'membership edits on a live channel require the operator role' => sub {
  my $relay    = _relay();
  my $op_grant = _seed_operator($relay);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_000,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $op_grant->id,
      extra_tags   => [['p', $attacker_key->pubkey_hex]],
    )
  );
  ok $accepted, 'an operator can add members to an existing channel' or diag $reason;

  my $attacker_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($attacker_grant);
  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_001,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $attacker_grant->id,
      extra_tags   => [['p', $operator_key->pubkey_hex]],
    )
  );
  ok !$accepted, 'a non-operator cannot remove members';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ channel\ operator/mx, 'operator-role reason';

  my $self_grant_control = _initial_operator_grant_control(
    session_key  => $attacker_session_key,
    actor_pubkey => $attacker_key->pubkey_hex,
    authority_id => $attacker_grant->id,
  );
  ($accepted, $reason) = _authorize($relay, $self_grant_control);
  ok !$accepted, 'a self-operator grant is not an initial grant once members exist';
};

subtest 'closed groups admit joins only through active invites' => sub {
  my $relay = _relay();
  _seed_operator($relay);
  $relay->store->store(_group_state_event(kind => 9_002, tags => [['closed']], created_at => $BASE_TIME + 5));
  $relay->store->store(
    _group_state_event(kind => 9_009, tags => [['code', 'sesame']], created_at => $BASE_TIME + 6));
  $relay->store->store(
    _group_state_event(
      kind       => 9_009,
      tags       => [['code', 'vip'], ['p', $attacker_key->pubkey_hex]],
      created_at => $BASE_TIME + 7,
    )
  );

  my $join = sub {
    my (%args) = @_;
    return _authorize(
      $relay,
      _join_request(
        relay       => $relay,
        actor_key   => $args{actor_key},
        session_key => $args{session_key},
        mask_tags   => $args{code_tags} || [],
      )
    );
  };

  my $joiner_key         = Net::Nostr::Key->new;
  my $joiner_session_key = Net::Nostr::Key->new;

  my ($accepted, $reason) = $join->(actor_key => $joiner_key, session_key => $joiner_session_key);
  ok !$accepted, 'a codeless join to a closed group is rejected';
  like $reason, qr/unauthorized:\ closed\ groups\ require\ an\ invite\ code/mx, 'codeless reason';

  ($accepted, $reason) = $join->(
    actor_key   => $joiner_key,
    session_key => $joiner_session_key,
    code_tags   => [['code', 'wrong']],
  );
  ok !$accepted, 'an unknown invite code is rejected';
  like $reason, qr/unauthorized:\ invite\ code\ is\ not\ active/mx, 'unknown code reason';

  ($accepted, $reason) = $join->(
    actor_key   => $joiner_key,
    session_key => $joiner_session_key,
    code_tags   => [['code', 'vip']],
  );
  ok !$accepted, 'a targeted invite cannot be used by another pubkey';
  like $reason, qr/unauthorized:\ invite\ code\ targets\ a\ different\ pubkey/mx, 'targeted code reason';

  ($accepted, $reason) = $join->(
    actor_key   => $joiner_key,
    session_key => $joiner_session_key,
    code_tags   => [['code', 'sesame']],
  );
  ok $accepted, 'an open invite code admits the join' or diag $reason;

  ($accepted, $reason) = $join->(
    actor_key   => $attacker_key,
    session_key => $attacker_session_key,
    code_tags   => [['code', 'vip']],
  );
  ok $accepted, 'a targeted invite admits its target' or diag $reason;

  ($accepted, $reason) = $join->(actor_key => $operator_key, session_key => $operator_session_key);
  ok $accepted, 'an existing member may re-join without a code' or diag $reason;
};

subtest 'leave requests require membership' => sub {
  my $relay = _relay();
  _seed_operator($relay);
  $relay->store->store(
    _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', $attacker_key->pubkey_hex]],
      created_at => $BASE_TIME + 5,
    )
  );

  my $attacker_grant = _grant_event(
    actor_key       => $attacker_key,
    delegate_pubkey => $attacker_session_key->pubkey_hex,
  );
  $relay->store->store($attacker_grant);
  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_022,
      session_key  => $attacker_session_key,
      actor_pubkey => $attacker_key->pubkey_hex,
      authority_id => $attacker_grant->id,
    )
  );
  ok $accepted, 'a joined member may leave' or diag $reason;

  my $stranger_key         = Net::Nostr::Key->new;
  my $stranger_session_key = Net::Nostr::Key->new;
  my $stranger_grant       = _grant_event(
    actor_key       => $stranger_key,
    delegate_pubkey => $stranger_session_key->pubkey_hex,
  );
  $relay->store->store($stranger_grant);
  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_022,
      session_key  => $stranger_session_key,
      actor_pubkey => $stranger_key->pubkey_hex,
      authority_id => $stranger_grant->id,
    )
  );
  ok !$accepted, 'a non-member leave request is rejected';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ group\ member/mx, 'non-member reason';
};

subtest 'actor membership derivation follows joins, invites, and removals' => sub {
  my $actor_key = Net::Nostr::Key->new;
  my $actor     = $actor_key->pubkey_hex;
  my $signers   = {$snapshot_key->pubkey_hex => 1};

  my $membership = sub {
    my (@events) = @_;
    my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
    $relay->store->store($_) for @events;
    return Overnet::Authority::HostedChannel::Relay::_actor_membership_state(
      relay            => $relay,
      group_id         => $GROUP_ID,
      snapshot_signers => $signers,
      actor            => $actor,
    );
  };

  is $membership->(), 0, 'no events derive no membership';

  my $member_snapshot = _snapshot_event(
    signer_key => $snapshot_key,
    kind       => 39_002,
    extra_tags => [['p', $actor]],
  );
  is $membership->($member_snapshot), 1, 'a member snapshot asserts membership';

  my $foreign_snapshot = _snapshot_event(
    signer_key => $snapshot_key,
    kind       => 39_002,
    extra_tags => [['p', $operator_key->pubkey_hex]],
  );
  is $membership->($foreign_snapshot), 0, 'a snapshot without the actor asserts non-membership';

  my $put_user = _group_state_event(kind => 9_000, tags => [['p', $actor]]);
  is $membership->($put_user), 1, 'a put-user event asserts membership';

  my $remove_user =
    _group_state_event(kind => 9_001, tags => [['p', $actor]], created_at => $BASE_TIME + 6);
  is $membership->($put_user, $remove_user), 0, 'a remove-user event revokes membership';

  my $remove_other = _group_state_event(
    kind       => 9_001,
    tags       => [['p', $operator_key->pubkey_hex]],
    created_at => $BASE_TIME + 6,
  );
  is $membership->($put_user, $remove_other), 1, 'removing another member preserves membership';

  my $open_join = _group_state_event(kind => 9_021, tags => [['overnet_actor', $actor]]);
  is $membership->($open_join), 1, 'an open-group join asserts membership';

  my $other_join =
    _group_state_event(kind => 9_021, tags => [['overnet_actor', $operator_key->pubkey_hex]]);
  is $membership->($other_join), 0, 'another actor joining says nothing about this actor';

  my $leave =
    _group_state_event(kind => 9_022, tags => [['overnet_actor', $actor]], created_at => $BASE_TIME + 6);
  is $membership->($open_join, $leave), 0, 'a leave event revokes membership';

  my $other_leave = _group_state_event(
    kind       => 9_022,
    tags       => [['overnet_actor', $operator_key->pubkey_hex]],
    created_at => $BASE_TIME + 6,
  );
  is $membership->($open_join, $other_leave), 1, 'another actor leaving preserves membership';

  my $codeless_invite = _group_state_event(kind => 9_009, tags => [], created_at => $BASE_TIME + 2);
  is $membership->($codeless_invite, $open_join), 1, 'a codeless invite event is ignored';

  my $closed = _group_state_event(kind => 9_002, tags => [['closed']], created_at => $BASE_TIME + 1);
  my $invite =
    _group_state_event(kind => 9_009, tags => [['code', 'sesame']], created_at => $BASE_TIME + 2);
  my $targeted = _group_state_event(
    kind       => 9_009,
    tags       => [['code', 'vip'], ['p', $operator_key->pubkey_hex]],
    created_at => $BASE_TIME + 2,
  );
  my $coded_join = sub {
    my ($code) = @_;
    return _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', $actor], ['code', $code]],
      created_at => $BASE_TIME + 3,
    );
  };

  is $membership->($closed, $invite, $coded_join->('sesame')), 1,
    'a closed-group join with a live invite asserts membership';
  is $membership->($closed, $invite, $coded_join->('wrong')), 0,
    'a closed-group join with an unknown code derives nothing';
  is $membership->($closed, $coded_join->('sesame')), 0,
    'a closed-group join without any invite derives nothing';
  is $membership->($closed, $targeted, $coded_join->('vip')), 0,
    'a closed-group join with a mistargeted invite derives nothing';

  my $tombstone = _group_state_event(
    kind       => 9_002,
    tags       => [['status', 'tombstoned']],
    created_at => $BASE_TIME + 9,
  );
  is $membership->($open_join, $tombstone), 0, 'a tombstoned group has no members';

  my $operator_snapshot = _snapshot_event(
    signer_key => $snapshot_key,
    kind       => 39_001,
    extra_tags => [['p', $actor, 'irc.operator']],
  );
  is $membership->($operator_snapshot), 0,
    'operator snapshots do not feed the actor membership derivation';

  is(
    Overnet::Authority::HostedChannel::Relay::_actor_membership_state(
      relay            => _relay(),
      group_id         => $GROUP_ID,
      snapshot_signers => {},
      actor            => 'not-a-pubkey',
    ),
    0,
    'a malformed actor pubkey derives no membership',
  );
};

subtest 'group event ordering breaks ties deterministically' => sub {
  my $compare = \&Overnet::Authority::HostedChannel::Relay::_compare_group_events;

  my $seq = sub {
    my (%args) = @_;
    return $operator_session_key->create_event(
      kind       => exists $args{kind} ? $args{kind} : 9_000,
      created_at => exists $args{created_at} ? $args{created_at} : $BASE_TIME,
      content    => exists $args{content} ? $args{content} : q{},
      tags       => [
        ['h', $GROUP_ID],
        (defined $args{sequence}  ? (['overnet_sequence',  $args{sequence}])  : ()),
        (defined $args{authority} ? (['overnet_authority', $args{authority}]) : ()),
      ],
    );
  };

  my $early = $seq->(created_at => $BASE_TIME);
  my $late  = $seq->(created_at => $BASE_TIME + 10);
  is $compare->($early, $late), -1, 'created_at orders first';

  my $first  = $seq->(sequence => '1', authority => 'a' x 64, content => 'one');
  my $second = $seq->(sequence => '2', authority => 'a' x 64, content => 'two');
  is $compare->($second, $first), 1, 'per-session sequence orders same-authority events';

  my $foreign = $seq->(sequence => '9', authority => 'b' x 64, content => 'other');
  my ($low_id, $high_id) = sort { lc($a->id) cmp lc($b->id) } ($first, $foreign);
  is $compare->($low_id, $high_id), -1,
    'sequences from different authorities fall through to the id tie-break';

  my $metadata = $seq->(kind => 39_000, content => 'ranked');
  my $put_user = $seq->(content => 'ranked put');
  is $compare->($metadata, $put_user), -1, 'semantic phase rank orders unsequenced ties';

  my $unranked = $operator_session_key->create_event(
    kind       => 1,
    created_at => $BASE_TIME,
    content    => 'chat events have no explicit rank',
    tags       => [['h', $GROUP_ID]],
  );
  is $compare->($put_user, $unranked), -1, 'unranked kinds sort after ranked kinds';

  my $malformed_a = $seq->(sequence => '0', authority => 'not-hex', content => 'zeroth');
  my $malformed_b = $seq->(sequence => '0', authority => 'not-hex', content => 'zeroth b');
  my ($tie_low, $tie_high) = sort { lc($a->id) cmp lc($b->id) } ($malformed_a, $malformed_b);
  is $compare->($tie_low, $tie_high), -1,
    'malformed sequence tags fall back to the id tie-break';

  my $unattributed_a = $seq->(sequence => '5', authority => 'not-hex', content => 'unattributed');
  my $unattributed_b = $seq->(sequence => '5', authority => 'not-hex', content => 'unattributed b');
  my ($ua_low, $ua_high) = sort { lc($a->id) cmp lc($b->id) } ($unattributed_a, $unattributed_b);
  is $compare->($ua_low, $ua_high), -1,
    'equal sequences with malformed authorities fall back to the id tie-break';
};

subtest 'group event scoping filters kinds, signers, and group ids' => sub {
  my $belongs = \&Overnet::Authority::HostedChannel::Relay::_event_belongs_to_group;
  my $signers = {$snapshot_key->pubkey_hex => 1};

  my $chat = $operator_session_key->create_event(
    kind       => 1,
    created_at => $BASE_TIME,
    content    => 'hi',
    tags       => [['h', $GROUP_ID]],
  );
  is $belongs->($chat, $GROUP_ID, $signers), 0, 'non-group kinds are excluded';

  my $forged_snapshot = _snapshot_event(signer_key => $attacker_key, kind => 39_001);
  is $belongs->($forged_snapshot, $GROUP_ID, $signers), 0,
    'snapshots from unconfigured signers are excluded';

  my $forged_metadata = _snapshot_event(signer_key => $attacker_key, kind => 39_000);
  is $belongs->($forged_metadata, $GROUP_ID, $signers), 0,
    'a 39000 event without delegation shape is excluded';

  my $delegated_metadata = $operator_session_key->create_event(
    kind       => 39_000,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => [
      ['d',                 $GROUP_ID],
      ['overnet_actor',     $operator_key->pubkey_hex],
      ['overnet_authority', 'a' x 64],
    ],
  );
  is $belongs->($delegated_metadata, $GROUP_ID, $signers), 1,
    'a delegated 39000 event with a matching d tag is included';

  my $control = _group_state_event(kind => 9_000, tags => [['p', 'c' x 64]]);
  is $belongs->($control, $GROUP_ID, $signers), 1, 'control events match on their h tag';
  is $belongs->($control, 'other-group', $signers), 0, 'other groups are excluded';
};

subtest 'group state derivation folds stored snapshots, joins, and removals' => sub {
  my $relay = _relay(snapshot_pubkeys => [$snapshot_key->pubkey_hex]);
  _seed_operator($relay);

  my $member_x = Net::Nostr::Key->new->pubkey_hex;
  my $member_y = Net::Nostr::Key->new->pubkey_hex;
  my $joiner_w_key         = Net::Nostr::Key->new;
  my $joiner_w             = $joiner_w_key->pubkey_hex;
  my $joiner_w_session_key = Net::Nostr::Key->new;

  $relay->store->store(
    _snapshot_event(
      signer_key => $snapshot_key,
      kind       => 39_002,
      created_at => $BASE_TIME + 2,
      extra_tags => [['p', $member_x], ['p', $member_x], ['p', 'not-a-pubkey'], ['q', 'noise'],],
    )
  );
  $relay->store->store(_group_state_event(kind => 9_000, tags => [], created_at => $BASE_TIME + 3));
  $relay->store->store(
    _group_state_event(kind => 9_000, tags => [['p', $member_y]], created_at => $BASE_TIME + 3));
  $relay->store->store(
    _group_state_event(kind => 9_001, tags => [['p', $member_y]], created_at => $BASE_TIME + 4));
  $relay->store->store(_group_state_event(kind => 9_001, tags => [], created_at => $BASE_TIME + 4));
  $relay->store->store(_group_state_event(kind => 9_009, tags => [], created_at => $BASE_TIME + 4));
  $relay->store->store(
    _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', 'not-a-pubkey']],
      created_at => $BASE_TIME + 5,
    )
  );
  $relay->store->store(
    _group_state_event(kind => 9_021, tags => [['overnet_actor', $joiner_w]], created_at => $BASE_TIME + 5));
  $relay->store->store(
    _group_state_event(kind => 9_021, tags => [['overnet_actor', $joiner_w]], created_at => $BASE_TIME + 6));
  $relay->store->store(
    _group_state_event(kind => 9_022, tags => [['overnet_actor', $member_x]], created_at => $BASE_TIME + 7));
  $relay->store->store(
    _group_state_event(
      kind       => 9_022,
      tags       => [['overnet_actor', 'not-a-pubkey']],
      created_at => $BASE_TIME + 7,
    )
  );

  my $leave_request = sub {
    my ($actor_key, $session_key) = @_;
    my $grant = _grant_event(actor_key => $actor_key, delegate_pubkey => $session_key->pubkey_hex);
    $relay->store->store($grant);
    return _authorize(
      $relay,
      _control_event(
        kind         => 9_022,
        session_key  => $session_key,
        actor_pubkey => $actor_key->pubkey_hex,
        authority_id => $grant->id,
      )
    );
  };

  my ($accepted, $reason) = $leave_request->($joiner_w_key, $joiner_w_session_key);
  ok $accepted, 'a joined member derived from stored events may leave' or diag $reason;
};

subtest 'closed group state consumes stored invite codes' => sub {
  my $relay = _relay();
  _seed_operator($relay);

  my $target_z             = Net::Nostr::Key->new->pubkey_hex;
  my $joiner_w_key         = Net::Nostr::Key->new;
  my $joiner_w             = $joiner_w_key->pubkey_hex;
  my $joiner_w_session_key = Net::Nostr::Key->new;

  $relay->store->store(_group_state_event(kind => 9_002, tags => [['closed']], created_at => $BASE_TIME + 2));
  $relay->store->store(
    _group_state_event(kind => 9_009, tags => [['code', 'vip'], ['p', $target_z]], created_at => $BASE_TIME + 3));
  $relay->store->store(
    _group_state_event(kind => 9_009, tags => [['code', 'own'], ['p', $joiner_w]], created_at => $BASE_TIME + 3));
  $relay->store->store(
    _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', $joiner_w], ['code', 'wrong']],
      created_at => $BASE_TIME + 4,
    )
  );
  $relay->store->store(
    _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', $joiner_w], ['code', 'vip']],
      created_at => $BASE_TIME + 5,
    )
  );
  $relay->store->store(
    _group_state_event(
      kind       => 9_021,
      tags       => [['overnet_actor', $joiner_w], ['code', 'own']],
      created_at => $BASE_TIME + 6,
    )
  );

  my $grant = _grant_event(
    actor_key       => $joiner_w_key,
    delegate_pubkey => $joiner_w_session_key->pubkey_hex,
  );
  $relay->store->store($grant);
  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_022,
      session_key  => $joiner_w_session_key,
      actor_pubkey => $joiner_w,
      authority_id => $grant->id,
    )
  );
  ok $accepted, 'only the correctly targeted stored invite admits the joiner' or diag $reason;
};

subtest 'operator actions require the irc.operator role specifically' => sub {
  my $relay    = _relay();
  my $op_grant = _seed_operator($relay);

  my $voice_key         = Net::Nostr::Key->new;
  my $voice_session_key = Net::Nostr::Key->new;

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_000,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $op_grant->id,
      extra_tags   => [['p', $voice_key->pubkey_hex, 'irc.voice']],
    )
  );
  ok $accepted, 'the operator can grant a non-operator role' or diag $reason;
  $relay->store->store(
    _group_state_event(
      kind       => 9_000,
      tags       => [['p', $voice_key->pubkey_hex, 'irc.voice']],
      created_at => $BASE_TIME + 11,
    )
  );

  my $voice_grant = _grant_event(
    actor_key       => $voice_key,
    delegate_pubkey => $voice_session_key->pubkey_hex,
  );
  $relay->store->store($voice_grant);
  ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_002,
      session_key  => $voice_session_key,
      actor_pubkey => $voice_key->pubkey_hex,
      authority_id => $voice_grant->id,
    )
  );
  ok !$accepted, 'a voiced member without the operator role cannot edit metadata';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ channel\ operator/mx, 'role-specific reason';
};

subtest 'derivation tolerates stores that return no event list' => sub {
  my $relay = build_authoritative_relay(
    relay_url  => $RELAY_URL,
    grant_kind => $GRANT_KIND,
    store      => _UndefStore->new,
  );

  my $grant = _grant_event(
    actor_key       => $operator_key,
    delegate_pubkey => $operator_session_key->pubkey_hex,
  );
  _authorize($relay, $grant);

  my ($accepted, $reason) = _authorize(
    $relay,
    _control_event(
      kind         => 9_022,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
    )
  );
  ok !$accepted, 'an eventless store derives an empty group';
  like $reason, qr/unauthorized:\ actor\ is\ not\ a\ group\ member/mx, 'empty-store leave reason';
};

subtest 'metadata and helper tag parsing tolerate malformed input' => sub {
  my %metadata = Overnet::Authority::HostedChannel::Relay::_metadata_from_tags(
    [
      [],
      ['closed'],
      ['open'],
      ['closed'],
      ['status', 'active'],
      ['status', 'tombstoned'],
      ['ban',    'alice!*@*'],
      ['ban',    'alice!*@*'],
      ['ban',    q{}],
      ['ban',    'bob!*@*'],
      ['ban'],
    ]
  );
  is $metadata{closed},     1, 'the last open/closed tag wins';
  is $metadata{tombstoned}, 1, 'any tombstoned status marks the group';
  is $metadata{ban_masks}, ['alice!*@*', 'bob!*@*'], 'ban masks are unique, non-empty, and sorted';

  ok Overnet::Authority::HostedChannel::Relay::_irc_mask_is_banned([undef, q{}, {}, 'alice!*@*'],
    'alice!u@host'),
    'malformed ban masks are skipped while matching';
  ok !Overnet::Authority::HostedChannel::Relay::_irc_mask_is_banned(['alice!*@*'], 'bob!u@host'),
    'non-matching masks are not banned';

  my ($code, $target) = Overnet::Authority::HostedChannel::Relay::_invite_from_tags(
    [['x'], ['code', 'first'], ['code', 'second'], ['p', 'a' x 64], ['p', 'b' x 64],]);
  is $code, 'first', 'the first invite code wins';
  is $target, 'a' x 64, 'the first target pubkey wins';

  is(Overnet::Authority::HostedChannel::Relay::_target_pubkey_from_tags([['q', 'x'], ['p']]),
    undef, 'a missing p tag yields no target',);

  my ($put_target, $roles) = Overnet::Authority::HostedChannel::Relay::_target_and_roles_from_put_user(
    [['p', 'NOT-HEX'], ['p', 'd' x 64, 'irc.operator', 'irc.voice'],]);
  is $put_target, 'd' x 64, 'malformed put-user pubkeys are skipped';
  is $roles, ['irc.operator', 'irc.voice'], 'put-user roles are extracted';

  my $unrelated = $operator_session_key->create_event(
    kind       => 1,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => [],
  );
  is(Overnet::Authority::HostedChannel::Relay::_apply_group_state_event({}, $unrelated),
    1, 'non-group kinds pass through group state application',);

  is {Overnet::Authority::HostedChannel::Relay::_first_tag_values(undef)}, {},
    'missing tag lists decode to no values';
  is {Overnet::Authority::HostedChannel::Relay::_first_tag_values([['e', 'one'], ['e', 'two']])},
    {e => 'one'}, 'repeated tag names keep their first value';
  is {Overnet::Authority::HostedChannel::Relay::_metadata_from_tags(undef)},
    {closed => 0, ban_masks => [], tombstoned => 0}, 'missing tags decode to default metadata';
  is Overnet::Authority::HostedChannel::Relay::_unique_non_empty_strings(undef), [],
    'missing string lists normalize to an empty list';
  is Overnet::Authority::HostedChannel::Relay::_irc_mask_is_banned(undef, 'alice!u@h'), 0,
    'no ban list bans nobody';
  is Overnet::Authority::HostedChannel::Relay::_irc_mask_is_banned(['alice!*@*'], q{}), 0,
    'an empty actor mask never matches';
  is [Overnet::Authority::HostedChannel::Relay::_target_and_roles_from_put_user(undef)],
    [undef, []], 'a tagless put-user has no target';
  is Overnet::Authority::HostedChannel::Relay::_target_pubkey_from_tags(undef), undef,
    'a tagless removal has no target';
  is [Overnet::Authority::HostedChannel::Relay::_invite_from_tags(undef)], [undef, undef],
    'a tagless invite has no code';
  is Overnet::Authority::HostedChannel::Relay::_has_role(undef, 'irc.operator'), 0,
    'missing role lists hold no roles';
  is [Overnet::Authority::HostedChannel::Relay::_member_tag_pubkey_and_roles(['p'])], [],
    'a p tag without a value is skipped';

  ok(Overnet::Authority::HostedChannel::Relay::_is_initial_operator_grant(
      {kind => 9_001, actor_pubkey => 'a' x 64}, {}
    ) == 0,
    'only put-user events can be initial operator grants',
  );
  my $minimal_join = $operator_session_key->create_event(
    kind       => 9_021,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => [['h', $GROUP_ID]],
  );
  ok(!Overnet::Authority::HostedChannel::Relay::_is_initial_operator_grant(
      {kind => 9_000, actor_pubkey => 'a' x 64, event => $minimal_join}, {}
    ),
    'a put-user event without a target is not an initial operator grant',
  );
  my ($accepted) = Overnet::Authority::HostedChannel::Relay::_authorize_join_request(
    event => $minimal_join,
    actor => 'e' x 64,
    state => {members => {}, invites => {}, closed => 0},
  );
  ok $accepted, 'a join into an open stateless group is accepted';
};

done_testing;
