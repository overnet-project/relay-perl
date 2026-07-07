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

done_testing;
