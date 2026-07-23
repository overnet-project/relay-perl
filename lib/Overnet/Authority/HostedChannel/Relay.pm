package Overnet::Authority::HostedChannel::Relay;

use strictures 2;

use Carp     qw(croak);
use Exporter qw(import);

our $VERSION   = '0.001';
our @EXPORT_OK = qw(build_authoritative_relay);

use Net::Nostr::Group;
use Net::Nostr::Relay;
use Overnet::Authority::HostedChannel ();
use Overnet::Relay::Store::File;

my %AUTHORITATIVE_CONTROL_KIND = map { $_ => 1 } (9_000, 9_001, 9_002, 9_009, 9_021, 9_022);
my %GROUP_SNAPSHOT_KIND        = map { $_ => 1 } (39_000, 39_001, 39_002, 39_003);
my %GROUP_EVENT_KIND           = map { $_ => 1 } (39_000, 39_001, 39_002, 9_000, 9_001, 9_002, 9_009, 9_021, 9_022);
my %EVENT_SORT_RANK            = (
  39_000 => 0,
  39_001 => 1,
  39_002 => 2,
  39_003 => 3,
  9_002  => 4,
  9_009  => 5,
  9_021  => 6,
  9_022  => 7,
  9_000  => 8,
  9_001  => 9,
);

sub build_authoritative_relay {
  my (%args) = @_;

  if (!(defined $args{relay_url} && !ref($args{relay_url}) && length($args{relay_url}))) {
    croak 'relay_url is required';
  }
  if (!(defined $args{grant_kind} && !ref($args{grant_kind}) && $args{grant_kind} =~ /\A[1-9]\d*\z/mxs)) {
    croak 'grant_kind must be a positive integer';
  }
  if (defined $args{store_file} && (ref($args{store_file}) || $args{store_file} eq q{})) {
    croak 'store_file must be a non-empty string';
  }
  my $snapshot_signers = _snapshot_signer_set($args{snapshot_pubkeys});

  my $relay;
  my %retained_grants;
  my %relay_args = (
    relay_url => $args{relay_url},
    on_event  => sub {
      my ($event) = @_;
      if ($event->kind == 0 + $args{grant_kind}) {
        _retain_grant(\%retained_grants, $event);
      }
      return _authorize_event(
        relay            => $relay,
        relay_url        => $args{relay_url},
        grant_kind       => 0 + $args{grant_kind},
        snapshot_signers => $snapshot_signers,
        retained_grants  => \%retained_grants,
        event            => $event,
      );
    },
  );

  if ($args{store}) {
    $relay_args{store} = $args{store};
  } elsif (defined $args{store_file}) {
    $relay_args{store} = Overnet::Relay::Store::File->new(path => $args{store_file},);
  }

  $relay = Net::Nostr::Relay->new(%relay_args);
  return $relay;
}

sub _snapshot_signer_set {
  my ($snapshot_pubkeys) = @_;
  if (!defined $snapshot_pubkeys) {
    return {};
  }
  if (ref($snapshot_pubkeys) ne 'ARRAY') {
    croak 'snapshot_pubkeys must be an array of 64-char lowercase hex pubkeys';
  }
  for my $pubkey (@{$snapshot_pubkeys}) {
    if (!_valid_pubkey($pubkey)) {
      croak 'snapshot_pubkeys must be an array of 64-char lowercase hex pubkeys';
    }
  }

  return {map { $_ => 1 } @{$snapshot_pubkeys}};
}

sub _authorize_event {
  my (%args) = @_;

  if ($GROUP_SNAPSHOT_KIND{$args{event}->kind}) {
    return _authorize_snapshot_event(%args);
  }

  my $context = _authorization_context(%args);

  if (!$context->{control_event}) {
    return _accept();
  }
  if (defined $context->{rejection}) {
    return _reject($context->{rejection});
  }

  my $grant_rejection = _verify_delegation_grant($context);
  if (defined $grant_rejection) {
    return _reject($grant_rejection);
  }

  my $state = _derive_group_state(
    relay            => $context->{relay},
    group_id         => $context->{group_id},
    snapshot_signers => $context->{snapshot_signers},
  );

  if ($state->{tombstoned}) {
    return _authorize_tombstoned_event($context, $state);
  }
  if ($context->{kind} == 9_021) {
    return _authorize_join_request(
      event => $context->{event},
      actor => $context->{actor_pubkey},
      state => $state,
    );
  }
  if ($context->{kind} == 9_022) {
    return _authorize_leave_request($context, $state);
  }
  if (_is_initial_operator_grant($context, $state)) {
    return _accept();
  }

  return _authorize_operator_action($context, $state);
}

sub _authorize_snapshot_event {
  my (%args) = @_;
  my $event = $args{event};

  if ($args{snapshot_signers}{$event->pubkey}) {
    return _accept();
  }
  if ($event->kind != 39_000) {
    return _reject('unauthorized: group snapshots require an authoritative snapshot identity');
  }

  my %tags     = _first_tag_values($event->tags);
  my $group_id = $tags{d};
  if (!(defined $group_id && !ref($group_id) && length($group_id))) {
    return _reject('invalid: authoritative group metadata events require one d tag');
  }

  my $context = _delegated_context(%args, group_id => $group_id);
  if (defined $context->{rejection}) {
    return _reject($context->{rejection});
  }
  my $grant_rejection = _verify_delegation_grant($context);
  if (defined $grant_rejection) {
    return _reject($grant_rejection);
  }

  my $state = _derive_group_state(
    relay            => $context->{relay},
    group_id         => $context->{group_id},
    snapshot_signers => $context->{snapshot_signers},
  );

  if ($state->{tombstoned}) {
    return _reject('unauthorized: group is tombstoned');
  }
  if (!keys %{$state->{members}}) {

    # The empty-group creation bootstrap establishes a channel; it must not also
    # tombstone it. A tombstone can only be reversed by a retained operator
    # (section 11.4), and an unclaimed group has none, so a bootstrap tombstone
    # would permanently and irrecoverably brick the channel name for its
    # legitimate owner. Refuse it; tombstoning is an operator action on an
    # established channel, not part of creating one.
    my %metadata = _metadata_from_tags($event->tags);
    if ($metadata{tombstoned}) {
      return _reject('unauthorized: an unclaimed group cannot be tombstoned before it has an operator');
    }
    return _accept();
  }

  return _authorize_operator_action($context, $state);
}

sub _authorization_context {
  my (%args) = @_;
  my $event  = $args{event};
  my $kind   = $event->kind;

  if (!$AUTHORITATIVE_CONTROL_KIND{$kind}) {
    return {control_event => 0};
  }

  my %tags     = _first_tag_values($event->tags);
  my $group_id = $tags{h};
  if (!(defined $group_id && !ref($group_id) && length($group_id))) {
    return _rejected_context('invalid: authoritative NIP-29 control events require one h tag');
  }

  return _delegated_context(%args, group_id => $group_id);
}

sub _delegated_context {
  my (%args) = @_;
  my $event  = $args{event};
  my %tags   = _first_tag_values($event->tags);

  my $actor_pubkey = $tags{overnet_actor};
  if (!_valid_pubkey($actor_pubkey)) {
    return _rejected_context('unauthorized: missing overnet_actor tag');
  }

  my $authority_id = $tags{overnet_authority};
  if (!_valid_pubkey($authority_id)) {
    return _rejected_context('unauthorized: missing overnet_authority tag');
  }

  if ($event->pubkey eq $actor_pubkey) {
    return _rejected_context('unauthorized: authority signer must differ from the effective actor');
  }

  return {
    control_event    => 1,
    relay            => $args{relay},
    relay_url        => $args{relay_url},
    grant_kind       => $args{grant_kind},
    snapshot_signers => $args{snapshot_signers},
    retained_grants  => $args{retained_grants},
    event            => $event,
    kind             => $event->kind,
    group_id         => $args{group_id},
    actor_pubkey     => $actor_pubkey,
    authority_id     => $authority_id,
  };
}

sub _retain_grant {
  my ($retained_grants, $grant) = @_;

  # Prune only grants that are expired against both the wall clock and the
  # incoming event's logical time, so a forged future created_at cannot
  # evict live grants and replayed histories keep their grant index.
  my $prune_before = time;
  if ($grant->created_at < $prune_before) {
    $prune_before = $grant->created_at;
  }
  for my $grant_id (keys %{$retained_grants}) {
    my %tags       = _first_tag_values($retained_grants->{$grant_id}->tags);
    my $expires_at = $tags{expires_at};
    if (defined $expires_at && !ref($expires_at) && $expires_at =~ /\A\d+\z/mxs && $expires_at < $prune_before) {
      delete $retained_grants->{$grant_id};
    }
  }

  $retained_grants->{$grant->id} = $grant;
  return 1;
}

sub _verify_delegation_grant {
  my ($context) = @_;
  my $grant = ($context->{retained_grants} || {})->{$context->{authority_id}}
    || $context->{relay}->store->get_by_id($context->{authority_id});
  if (!$grant) {
    return 'unauthorized: delegation grant is not known to this relay';
  }
  if ($grant->kind != $context->{grant_kind}) {
    return 'unauthorized: delegation grant uses the wrong event kind';
  }
  if ($grant->pubkey ne $context->{actor_pubkey}) {
    return 'unauthorized: delegation grant is not signed by the effective actor';
  }

  my %tags = _first_tag_values($grant->tags);
  if (!(defined $tags{delegate} && !ref($tags{delegate}) && $tags{delegate} eq $context->{event}->pubkey)) {
    return 'unauthorized: delegation grant does not delegate to the event signer';
  }
  if (!(defined $tags{relay} && !ref($tags{relay}) && $tags{relay} eq $context->{relay_url})) {
    return 'unauthorized: delegation grant is bound to a different relay';
  }
  for my $required_tag (qw(server session)) {
    if (!(defined $tags{$required_tag} && !ref($tags{$required_tag}) && length($tags{$required_tag}))) {
      return 'unauthorized: delegation grant is missing required tags';
    }
  }
  my $expires_at = $tags{expires_at};
  if (
    !(
         defined $expires_at
      && !ref($expires_at)
      && $expires_at =~ /\A\d+\z/mxs
      && $context->{event}->created_at <= $expires_at
    )
  ) {
    return 'unauthorized: delegation grant has expired';
  }

  return;
}

sub _rejected_context {
  my ($reason) = @_;
  return {
    control_event => 1,
    rejection     => $reason,
  };
}

sub _accept {
  return (1, q{});
}

sub _reject {
  my ($reason) = @_;
  return (0, $reason);
}

sub _authorize_tombstoned_event {
  my ($context, $state) = @_;
  if ($context->{kind} == 9_002) {
    my %metadata = _metadata_from_tags($context->{event}->tags);
    if (!$metadata{tombstoned}) {
      if (_actor_has_operator_role($state, $context->{actor_pubkey})) {
        return _accept();
      }
      return _reject('unauthorized: actor is not a retained channel operator');
    }
  }

  return _reject('unauthorized: group is tombstoned');
}

sub _authorize_leave_request {
  my ($context, $state) = @_;
  if (
    $state->{members}{$context->{actor_pubkey}}
    || _actor_membership_state(
      relay            => $context->{relay},
      group_id         => $context->{group_id},
      snapshot_signers => $context->{snapshot_signers},
      actor            => $context->{actor_pubkey},
    )
  ) {
    return _accept();
  }

  return _reject('unauthorized: actor is not a group member');
}

sub _is_initial_operator_grant {
  my ($context, $state) = @_;
  if ($context->{kind} != 9_000) {
    return 0;
  }
  if (keys %{$state->{members} || {}}) {
    return 0;
  }

  my ($target_pubkey, $roles) = _target_and_roles_from_put_user($context->{event}->tags);
  return
       defined $target_pubkey
    && $target_pubkey eq $context->{actor_pubkey}
    && _has_role($roles, 'irc.operator');
}

sub _authorize_operator_action {
  my ($context, $state) = @_;
  if (_actor_has_operator_role($state, $context->{actor_pubkey})) {
    return _accept();
  }

  return _reject('unauthorized: actor is not a channel operator');
}

sub _actor_has_operator_role {
  my ($state, $actor_pubkey) = @_;
  my $member = $state->{members}{$actor_pubkey};
  return $member && _has_role($member->{roles}, 'irc.operator') ? 1 : 0;
}

sub _has_role {
  my ($roles, $role) = @_;
  for my $candidate (@{$roles || []}) {
    if ($candidate eq $role) {
      return 1;
    }
  }

  return 0;
}

sub _authorize_join_request {
  my (%args) = @_;
  my $event  = $args{event};
  my $actor  = $args{actor};
  my $state  = $args{state};

  if ($state->{members}{$actor}) {
    return _accept();
  }

  my %tags       = _first_tag_values($event->tags);
  my $actor_mask = $tags{overnet_irc_mask};
  my $has_bans   = @{$state->{ban_masks} || []}                                    ? 1 : 0;
  my $valid_mask = defined $actor_mask && !ref($actor_mask) && length($actor_mask) ? 1 : 0;
  if ($has_bans && !$valid_mask) {
    return _reject('unauthorized: join request must assert an IRC mask while bans are active');
  }
  if (_irc_mask_is_banned($state->{ban_masks}, $actor_mask)) {
    return _reject('unauthorized: actor is banned from the group');
  }

  if (!$state->{closed}) {
    return _accept();
  }

  my $code = $tags{code};
  if (!(defined $code && length($code))) {
    return _reject('unauthorized: closed groups require an invite code');
  }
  if (!exists $state->{invites}{$code}) {
    return _reject('unauthorized: invite code is not active');
  }

  my $invite = $state->{invites}{$code};
  if (defined $invite->{target_pubkey} && $invite->{target_pubkey} ne $actor) {
    return _reject('unauthorized: invite code targets a different pubkey');
  }

  return _accept();
}

sub _derive_group_state {
  my (%args) = @_;
  my $state = _new_group_state();

  for my $event (_group_events($args{relay}, $args{group_id}, $args{snapshot_signers})) {
    _apply_group_state_event($state, $event);
  }

  return {
    closed     => $state->{closed},
    ban_masks  => [@{$state->{ban_masks}}],
    members    => $state->{members},
    invites    => $state->{invites},
    tombstoned => $state->{tombstoned} ? 1 : 0,
  };
}

sub _new_group_state {
  return {
    closed     => 0,
    ban_masks  => [],
    members    => {},
    invites    => {},
    tombstoned => 0,
  };
}

sub _apply_group_state_event {
  my ($state, $event) = @_;
  my $kind = $event->kind;

  if ($kind == 39_000 || $kind == 9_002) {
    return _apply_group_metadata_event($state, $event);
  }
  if ($kind == 39_001) {
    return _apply_operator_snapshot_event($state, $event);
  }
  if ($kind == 39_002) {
    return _apply_member_snapshot_event($state, $event);
  }
  if ($kind == 9_000) {
    return _apply_put_user_event($state, $event);
  }
  if ($kind == 9_001) {
    return _apply_remove_user_event($state, $event);
  }
  if ($kind == 9_009) {
    return _apply_invite_event($state, $event);
  }
  if ($kind == 9_021) {
    return _apply_join_event($state, $event);
  }
  if ($kind == 9_022) {
    return _apply_leave_event($state, $event);
  }

  return 1;
}

sub _apply_group_metadata_event {
  my ($state, $event) = @_;
  my %metadata = _metadata_from_tags($event->tags);
  $state->{closed} = $metadata{closed} ? 1 : 0;

  # uncoverable branch true reason: _metadata_from_tags always returns an array reference for ban_masks
  $state->{ban_masks}  = [@{$metadata{ban_masks} || []}];
  $state->{tombstoned} = $metadata{tombstoned} ? 1 : 0;
  if ($state->{tombstoned}) {
    $state->{invites} = {};
  }

  return 1;
}

sub _apply_operator_snapshot_event {
  my ($state, $event) = @_;

  # uncoverable branch true reason: Net::Nostr::Event tags always default to an array reference
  for my $tag (@{$event->tags || []}) {
    my ($pubkey, $roles) = _member_tag_pubkey_and_roles($tag);
    if (!defined $pubkey) {
      next;
    }
    $state->{members}{$pubkey} = {
      pubkey => $pubkey,
      roles  => $roles,
    };
  }

  return 1;
}

sub _apply_member_snapshot_event {
  my ($state, $event) = @_;

  # uncoverable branch true reason: Net::Nostr::Event tags always default to an array reference
  for my $tag (@{$event->tags || []}) {
    my ($pubkey) = _member_tag_pubkey_and_roles($tag);
    if (!defined $pubkey) {
      next;
    }
    if (!exists $state->{members}{$pubkey}) {
      $state->{members}{$pubkey} = {
        pubkey => $pubkey,
        roles  => [],
      };
    }
  }

  return 1;
}

sub _apply_put_user_event {
  my ($state,         $event) = @_;
  my ($target_pubkey, $roles) = _target_and_roles_from_put_user($event->tags);
  if (defined $target_pubkey) {
    $state->{members}{$target_pubkey} = {
      pubkey => $target_pubkey,
      roles  => $roles,
    };
  }

  return 1;
}

sub _apply_remove_user_event {
  my ($state, $event) = @_;
  my $target_pubkey = _target_pubkey_from_tags($event->tags);
  if (defined $target_pubkey) {
    delete $state->{members}{$target_pubkey};
  }

  return 1;
}

sub _apply_invite_event {
  my ($state, $event)         = @_;
  my ($code,  $target_pubkey) = _invite_from_tags($event->tags);
  if (defined $code) {
    $state->{invites}{$code} = {
      code => $code,
      (defined $target_pubkey ? (target_pubkey => $target_pubkey) : ()),
    };
  }

  return 1;
}

sub _apply_join_event {
  my ($state, $event) = @_;
  my %tags   = _first_tag_values($event->tags);
  my $joiner = $tags{overnet_actor};
  if (!_valid_pubkey($joiner)) {
    return 1;
  }
  if (!$state->{closed}) {
    _add_default_member($state, $joiner);
    return 1;
  }

  my $code = $tags{code};
  if (!(defined $code && exists $state->{invites}{$code})) {
    return 1;
  }

  my $invite = $state->{invites}{$code};
  if (defined $invite->{target_pubkey} && $invite->{target_pubkey} ne $joiner) {
    return 1;
  }

  _add_default_member($state, $joiner);
  delete $state->{invites}{$code};
  return 1;
}

sub _apply_leave_event {
  my ($state, $event) = @_;
  my %tags   = _first_tag_values($event->tags);
  my $leaver = $tags{overnet_actor};
  if (_valid_pubkey($leaver)) {
    delete $state->{members}{$leaver};
  }

  return 1;
}

sub _add_default_member {
  my ($state, $pubkey) = @_;
  if (!exists $state->{members}{$pubkey}) {
    $state->{members}{$pubkey} = {
      pubkey => $pubkey,
      roles  => [],
    };
  }

  return 1;
}

sub _member_tag_pubkey_and_roles {
  my ($tag) = @_;
  if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || q{}) eq 'p')) {
    return;
  }
  if (!_valid_pubkey($tag->[1])) {
    return;
  }

  return ($tag->[1], [@{$tag}[2 .. $#{$tag}]]);
}

sub _actor_membership_state {
  my (%args) = @_;
  if (!_valid_pubkey($args{actor})) {
    return 0;
  }

  my $state = {
    actor      => $args{actor},
    closed     => 0,
    member     => 0,
    invites    => {},
    tombstoned => 0,
  };

  for my $event (_group_events($args{relay}, $args{group_id}, $args{snapshot_signers})) {
    _apply_actor_membership_event($state, $event);
  }

  if ($state->{tombstoned}) {
    return 0;
  }
  return $state->{member};
}

sub _apply_actor_membership_event {
  my ($state, $event) = @_;
  my $kind = $event->kind;

  if ($kind == 39_000 || $kind == 9_002) {
    return _apply_actor_metadata_event($state, $event);
  }
  if ($kind == 39_002) {
    return _apply_actor_snapshot_event($state, $event);
  }
  if ($kind == 9_009) {
    return _apply_actor_invite_event($state, $event);
  }
  if ($kind == 9_000) {
    return _apply_actor_put_user_event($state, $event);
  }
  if ($kind == 9_001) {
    return _apply_actor_remove_user_event($state, $event);
  }
  if ($kind == 9_021) {
    return _apply_actor_join_event($state, $event);
  }
  if ($kind == 9_022) {
    return _apply_actor_leave_event($state, $event);
  }

  return 1;
}

sub _apply_actor_metadata_event {
  my ($state, $event) = @_;
  my %metadata = _metadata_from_tags($event->tags);
  $state->{closed}     = $metadata{closed}     ? 1 : 0;
  $state->{tombstoned} = $metadata{tombstoned} ? 1 : 0;
  if ($state->{tombstoned}) {
    $state->{invites} = {};
  }

  return 1;
}

sub _apply_actor_snapshot_event {
  my ($state, $event) = @_;
  my $member_info = Net::Nostr::Group->members_from_event($event);

  # uncoverable branch true reason: Net::Nostr::Group always returns an array reference for members
  my %snapshot = map { $_ => 1 } @{$member_info->{members} || []};
  $state->{member} = $snapshot{$state->{actor}} ? 1 : 0;
  return 1;
}

sub _apply_actor_invite_event {
  my ($state, $event)         = @_;
  my ($code,  $target_pubkey) = _invite_from_tags($event->tags);
  if (defined $code) {
    $state->{invites}{$code} = {(defined $target_pubkey ? (target_pubkey => $target_pubkey) : ()),};
  }

  return 1;
}

sub _apply_actor_put_user_event {
  my ($state, $event) = @_;
  my ($target_pubkey) = _target_and_roles_from_put_user($event->tags);
  if (defined $target_pubkey && $target_pubkey eq $state->{actor}) {
    $state->{member} = 1;
  }

  return 1;
}

sub _apply_actor_remove_user_event {
  my ($state, $event) = @_;
  my $target_pubkey = _target_pubkey_from_tags($event->tags);
  if (defined $target_pubkey && $target_pubkey eq $state->{actor}) {
    $state->{member} = 0;
  }

  return 1;
}

sub _apply_actor_join_event {
  my ($state, $event) = @_;
  my %tags = _first_tag_values($event->tags);
  if (!(defined $tags{overnet_actor} && $tags{overnet_actor} eq $state->{actor})) {
    return 1;
  }
  if (!$state->{closed}) {
    $state->{member} = 1;
    return 1;
  }

  my $code = $tags{code};
  if (!(defined $code && exists $state->{invites}{$code})) {
    return 1;
  }

  my $invite = $state->{invites}{$code};
  if (defined $invite->{target_pubkey} && $invite->{target_pubkey} ne $state->{actor}) {
    return 1;
  }

  $state->{member} = 1;
  delete $state->{invites}{$code};
  return 1;
}

sub _apply_actor_leave_event {
  my ($state, $event) = @_;
  my %tags = _first_tag_values($event->tags);
  if (defined $tags{overnet_actor} && $tags{overnet_actor} eq $state->{actor}) {
    $state->{member} = 0;
  }

  return 1;
}

sub _group_events {
  my ($relay, $group_id, $snapshot_signers) = @_;
  my @events;

  for my $event (@{$relay->store->all_events || []}) {
    if (_event_belongs_to_group($event, $group_id, $snapshot_signers)) {
      push @events, $event;
    }
  }

  my @ordered = sort { _compare_group_events($a, $b) } @events;
  return @ordered;
}

sub _event_belongs_to_group {
  my ($event, $group_id, $snapshot_signers) = @_;
  if (!$GROUP_EVENT_KIND{$event->kind}) {
    return 0;
  }
  if ($GROUP_SNAPSHOT_KIND{$event->kind} && !($snapshot_signers || {})->{$event->pubkey}) {
    if ($event->kind != 39_000) {
      return 0;
    }
    if (!_event_has_delegation_shape($event)) {
      return 0;
    }
  }

  # Bind the event to a group by the SAME tag its authorization used: snapshot
  # events (39xxx) are authorized and addressed by their `d` tag, control events
  # (9xxx) by their `h` tag. Matching the other tag too would let an event
  # authorized against one group (say an empty group an attacker bootstraps for
  # free) be folded into a different, established group's derived state, escaping
  # that group's authorization entirely.
  my %tags        = _first_tag_values($event->tags);
  my $binding_tag = $GROUP_SNAPSHOT_KIND{$event->kind} ? 'd' : 'h';
  return defined $tags{$binding_tag} && $tags{$binding_tag} eq $group_id ? 1 : 0;
}

sub _event_has_delegation_shape {
  my ($event) = @_;
  my %tags = _first_tag_values($event->tags);
  return
       _valid_pubkey($tags{overnet_actor})
    && _valid_pubkey($tags{overnet_authority})
    && $event->pubkey ne $tags{overnet_actor} ? 1 : 0;
}

sub _compare_group_events {
  my ($first_event, $second_event) = @_;
  my $created_order = $first_event->created_at <=> $second_event->created_at;
  if ($created_order) {
    return $created_order;
  }

  # Preserve explicit per-session causal order only when it actually
  # distinguishes the two events; an equal (or absent) sequence must fall
  # through to the semantic phase and event-id tie-breaks below.
  my $sequence_order = _compare_event_sequence_for_sort($first_event, $second_event);
  if ($sequence_order) {
    return $sequence_order;
  }

  my $rank_order = _event_sort_rank($first_event) <=> _event_sort_rank($second_event);
  if ($rank_order) {
    return $rank_order;
  }

  # irc.md section 11.4: remaining ties MUST break by ascending lowercase Nostr
  # event id, never by raw local input position.
  return lc($first_event->id) cmp lc($second_event->id);
}

sub _compare_event_sequence_for_sort {
  my ($first_event, $second_event) = @_;
  my $first_sequence  = _event_sequence_for_sort($first_event);
  my $second_sequence = _event_sequence_for_sort($second_event);
  if (!(defined $first_sequence && defined $second_sequence)) {
    return;
  }

  my $first_authority  = _event_authority_for_sort($first_event)  || q{};
  my $second_authority = _event_authority_for_sort($second_event) || q{};
  if ($first_authority ne $second_authority) {
    return;
  }

  return $first_sequence <=> $second_sequence;
}

sub _event_authority_for_sort {
  my ($event) = @_;
  my %tags = _first_tag_values($event->tags);
  if ( defined $tags{overnet_authority}
    && !ref($tags{overnet_authority})
    && $tags{overnet_authority} =~ /\A[0-9a-f]{64}\z/mxs) {
    return $tags{overnet_authority};
  }
  return;
}

sub _event_sequence_for_sort {
  my ($event) = @_;
  my %tags = _first_tag_values($event->tags);
  if ( defined $tags{overnet_sequence}
    && !ref($tags{overnet_sequence})
    && $tags{overnet_sequence} =~ /\A[1-9]\d*\z/mxs) {
    return 0 + $tags{overnet_sequence};
  }
  return;
}

sub _event_sort_rank {
  my ($event) = @_;
  if (exists $EVENT_SORT_RANK{$event->kind}) {
    return $EVENT_SORT_RANK{$event->kind};
  }
  return 99;
}

sub _metadata_from_tags {
  my ($tags) = @_;
  my %metadata = (
    closed     => 0,
    ban_masks  => [],
    tombstoned => 0,
  );

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 1)) {
      next;
    }
    my $tag_name = $tag->[0] || q{};
    if ($tag_name eq 'closed') {
      $metadata{closed} = 1;
    }
    if ($tag_name eq 'open') {
      $metadata{closed} = 0;
    }
    if ($tag_name eq 'status' && @{$tag} >= 2 && ($tag->[1] || q{}) eq 'tombstoned') {
      $metadata{tombstoned} = 1;
    }
    if ($tag_name eq 'ban' && @{$tag} >= 2) {
      push @{$metadata{ban_masks}}, $tag->[1];
    }
  }

  $metadata{ban_masks} = _unique_non_empty_strings($metadata{ban_masks});
  return %metadata;
}

sub _unique_non_empty_strings {
  my ($values) = @_;
  my %seen;
  my @unique;
  for my $value (@{$values || []}) {
    if (!(defined $value && !ref($value) && length($value))) {
      next;
    }
    if ($seen{$value}++) {
      next;
    }
    push @unique, $value;
  }

  return [sort @unique];
}

sub _irc_mask_is_banned {
  my ($ban_masks, $actor_mask) = @_;
  if (!(defined $actor_mask && !ref($actor_mask) && length($actor_mask))) {
    return 0;
  }

  for my $ban_mask (@{$ban_masks || []}) {
    if (!(defined $ban_mask && !ref($ban_mask) && length($ban_mask))) {
      next;
    }
    if (
      Overnet::Authority::HostedChannel::irc_mask_matches(
        mask  => $ban_mask,
        value => $actor_mask,
      )
    ) {
      return 1;
    }
  }

  return 0;
}

sub _target_and_roles_from_put_user {
  my ($tags) = @_;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || q{}) eq 'p')) {
      next;
    }
    my $pubkey = $tag->[1];
    if (!_valid_pubkey($pubkey)) {
      next;
    }
    return ($pubkey, [@{$tag}[2 .. $#{$tag}]]);
  }

  return (undef, []);
}

sub _target_pubkey_from_tags {
  my ($tags) = @_;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || q{}) eq 'p')) {
      next;
    }
    return $tag->[1];
  }

  return;
}

sub _invite_from_tags {
  my ($tags) = @_;
  my $code;
  my $target_pubkey;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    my $tag_name = $tag->[0] || q{};
    if (!defined($code) && $tag_name eq 'code') {
      $code = $tag->[1];
    }
    if (!defined($target_pubkey) && $tag_name eq 'p') {
      $target_pubkey = $tag->[1];
    }
  }

  return ($code, $target_pubkey);
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _valid_pubkey {
  my ($pubkey) = @_;
  return defined $pubkey && !ref($pubkey) && $pubkey =~ /\A[0-9a-f]{64}\z/mxs ? 1 : 0;
}

1;

=head1 NAME

Overnet::Authority::HostedChannel::Relay - Authoritative hosted-channel relay builder

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $relay = build_authoritative_relay(
    relay_url        => 'ws://127.0.0.1:7777',
    grant_kind       => 14142,
    snapshot_pubkeys => ['0f' x 32],
  );

=head1 DESCRIPTION

Builds a relay with NIP-29 hosted-channel authorization rules for Overnet IRC
authority operation.

Control events (kinds 9000, 9001, 9002, 9009, 9021, and 9022) are accepted
only when their C<overnet_authority> tag resolves to a delegation grant event
stored at this relay that has the configured grant kind, is signed by the
event's C<overnet_actor> pubkey, delegates to the event's signing pubkey, is
bound to this relay's URL, carries C<server> and C<session> tags, and is
unexpired at the control event's C<created_at>.

Group snapshot events of kinds 39001, 39002, and 39003 are accepted, and
folded into derived authoritative group state, only when signed by one of the
configured C<snapshot_pubkeys>. Kind 39000 group metadata is additionally
accepted as a delegated authoritative write under the same grant verification
as control events, when the effective actor is a current channel operator or
the bound group has no durable members yet (the hosted-channel creation
bootstrap); delegated 39000 events are rejected for tombstoned groups. When
no snapshot identity is configured, snapshot-kind events without a verified
delegation are rejected.

The C<overnet_irc_mask> tag on a C<9021> join request is asserted by the
publisher, so relay-side C<+b> mask-ban enforcement is best-effort: this relay
cannot observe the joining client's real IRC mask. To close the trivial
evasion of simply omitting the mask, a join request to a group that has any
active ban mask is rejected unless it carries a well-formed non-empty
C<overnet_irc_mask>. The authoritative, non-evadable exclusion mechanism
remains C<9001> pubkey removal on a C<closed> channel.

=head1 SUBROUTINES/METHODS

=head2 build_authoritative_relay

Creates a relay configured with hosted-channel authorization hooks. Accepts
C<relay_url>, C<grant_kind>, optional C<store> or C<store_file>, and optional
C<snapshot_pubkeys> (an array reference of 64-character lowercase hex pubkeys
allowed to sign authoritative group snapshots).

=head1 DIAGNOSTICS

Invalid constructor arguments are reported with C<croak>. Unauthorized events
return Nostr relay rejection reasons.

=head1 CONFIGURATION AND ENVIRONMENT

The caller supplies the relay URL, grant kind, and optional store.

=head1 DEPENDENCIES

Requires L<Net::Nostr::Group>, L<Net::Nostr::Relay>, and Overnet relay modules.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
