package Overnet::Authority::HostedChannel::Relay;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT_OK = qw(build_authoritative_relay);

use Net::Nostr::Group;
use Net::Nostr::Relay;
use Overnet::Authority::HostedChannel ();
use Overnet::Relay::Store::File;

sub build_authoritative_relay {
  my (%args) = @_;

  die "relay_url is required\n"
    unless defined $args{relay_url} && !ref($args{relay_url}) && length($args{relay_url});
  die "grant_kind must be a positive integer\n"
    unless defined $args{grant_kind}
      && !ref($args{grant_kind})
      && $args{grant_kind} =~ /\A[1-9]\d*\z/;
  die "store_file must be a non-empty string\n"
    if defined $args{store_file} && (ref($args{store_file}) || $args{store_file} eq '');

  my $relay;
  my %relay_args = (
    relay_url => $args{relay_url},
    on_event  => sub {
      my ($event) = @_;
      return _authorize_event(
        relay      => $relay,
        relay_url  => $args{relay_url},
        grant_kind => 0 + $args{grant_kind},
        event      => $event,
      );
    },
  );

  if ($args{store}) {
    $relay_args{store} = $args{store};
  } elsif (defined $args{store_file}) {
    $relay_args{store} = Overnet::Relay::Store::File->new(
      path => $args{store_file},
    );
  }

  $relay = Net::Nostr::Relay->new(%relay_args);
  return $relay;
}

sub _authorize_event {
  my (%args) = @_;
  my $relay = $args{relay};
  my $event = $args{event};

  my $kind = $event->kind;
  return (1, '') unless $kind == 9000
    || $kind == 9001
    || $kind == 9002
    || $kind == 9009
    || $kind == 9021
    || $kind == 9022;

  my %tags = _first_tag_values($event->tags);
  my $group_id = $tags{h};
  return (0, 'invalid: authoritative NIP-29 control events require one h tag')
    unless defined $group_id && !ref($group_id) && length($group_id);

  my $actor_pubkey = $tags{overnet_actor};
  return (0, 'unauthorized: missing overnet_actor tag')
    unless defined $actor_pubkey && $actor_pubkey =~ /\A[0-9a-f]{64}\z/;

  my $authority_id = $tags{overnet_authority};
  return (0, 'unauthorized: missing overnet_authority tag')
    unless defined $authority_id && $authority_id =~ /\A[0-9a-f]{64}\z/;

  return (0, 'unauthorized: authority signer must differ from the effective actor')
    if $event->pubkey eq $actor_pubkey;

  my $state = _derive_group_state(
    relay    => $relay,
    group_id => $group_id,
  );

  if ($state->{tombstoned}) {
    if ($kind == 9002) {
      my %metadata = _metadata_from_tags($event->tags);
      if (!$metadata{tombstoned}) {
        my $member = $state->{members}{$actor_pubkey};
        return (0, 'unauthorized: actor is not a retained channel operator')
          unless $member && grep { $_ eq 'irc.operator' } @{$member->{roles} || []};
        return (1, '');
      }
    }
    return (0, 'unauthorized: group is tombstoned');
  }

  if ($kind == 9021) {
    return _authorize_join_request(
      event      => $event,
      actor      => $actor_pubkey,
      state      => $state,
    );
  }

  if ($kind == 9022) {
    return (1, '')
      if $state->{members}{$actor_pubkey}
        || _actor_membership_state(
          relay    => $relay,
          group_id => $group_id,
          actor    => $actor_pubkey,
        );
    return (0, 'unauthorized: actor is not a group member');
  }

  if ($kind == 9000) {
    my ($target_pubkey, $roles) = _target_and_roles_from_put_user($event->tags);
    if (!keys %{$state->{members} || {}}
        && defined $target_pubkey
        && $target_pubkey eq $actor_pubkey
        && grep { $_ eq 'irc.operator' } @{$roles || []}) {
      return (1, '');
    }
  }

  my $member = $state->{members}{$actor_pubkey};
  return (0, 'unauthorized: actor is not a channel operator')
    unless $member && grep { $_ eq 'irc.operator' } @{$member->{roles} || []};

  return (1, '');
}

sub _authorize_join_request {
  my (%args) = @_;
  my $event = $args{event};
  my $actor = $args{actor};
  my $state = $args{state};

  return (1, '')
    if $state->{members}{$actor};

  my %tags = _first_tag_values($event->tags);
  if (_irc_mask_is_banned($state->{ban_masks}, $tags{overnet_irc_mask})) {
    return (0, 'unauthorized: actor is banned from the group');
  }

  return (1, '')
    unless $state->{closed};

  my $code = $tags{code};
  return (0, 'unauthorized: closed groups require an invite code')
    unless defined $code && length($code);
  return (0, 'unauthorized: invite code is not active')
    unless exists $state->{invites}{$code};

  my $invite = $state->{invites}{$code};
  if (defined $invite->{target_pubkey} && $invite->{target_pubkey} ne $actor) {
    return (0, 'unauthorized: invite code targets a different pubkey');
  }

  return (1, '');
}

sub _derive_group_state {
  my (%args) = @_;
  my $relay = $args{relay};
  my $group_id = $args{group_id};

  my %members;
  my %invites;
  my $closed = 0;
  my @ban_masks;
  my $tombstoned = 0;

  for my $event (_group_events($relay, $group_id)) {
    my $kind = $event->kind;

    if ($kind == 39000 || $kind == 9002) {
      my %metadata = _metadata_from_tags($event->tags);
      $closed = $metadata{closed} ? 1 : 0;
      @ban_masks = @{$metadata{ban_masks} || []};
      $tombstoned = $metadata{tombstoned} ? 1 : 0;
      %invites = ()
        if $tombstoned;
      next;
    }

    if ($kind == 39001) {
      for my $tag (@{$event->tags || []}) {
        next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || '') eq 'p';
        my $pubkey = $tag->[1];
        next unless defined $pubkey && $pubkey =~ /\A[0-9a-f]{64}\z/;
        $members{$pubkey} = {
          pubkey => $pubkey,
          roles  => [ @{$tag}[2 .. $#{$tag}] ],
        };
      }
      next;
    }

    if ($kind == 39002) {
      for my $tag (@{$event->tags || []}) {
        next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || '') eq 'p';
        my $pubkey = $tag->[1];
        next unless defined $pubkey && $pubkey =~ /\A[0-9a-f]{64}\z/;
        $members{$pubkey} ||= {
          pubkey => $pubkey,
          roles  => [],
        };
      }
      next;
    }

    if ($kind == 9000) {
      my ($target_pubkey, $roles) = _target_and_roles_from_put_user($event->tags);
      next unless defined $target_pubkey;
      $members{$target_pubkey} = {
        pubkey => $target_pubkey,
        roles  => $roles,
      };
      next;
    }

    if ($kind == 9001) {
      my $target_pubkey = _target_pubkey_from_tags($event->tags);
      delete $members{$target_pubkey}
        if defined $target_pubkey;
      next;
    }

    if ($kind == 9009) {
      my ($code, $target_pubkey) = _invite_from_tags($event->tags);
      next unless defined $code;
      $invites{$code} = {
        code => $code,
        (defined $target_pubkey ? (target_pubkey => $target_pubkey) : ()),
      };
      next;
    }

    if ($kind == 9021) {
      my %tags = _first_tag_values($event->tags);
      my $joiner = $tags{overnet_actor};
      next unless defined $joiner && $joiner =~ /\A[0-9a-f]{64}\z/;

      if (!$closed) {
        $members{$joiner} ||= {
          pubkey => $joiner,
          roles  => [],
        };
        next;
      }

      my $code = $tags{code};
      next unless defined $code && exists $invites{$code};

      my $invite = $invites{$code};
      next if defined $invite->{target_pubkey}
        && $invite->{target_pubkey} ne $joiner;

      $members{$joiner} ||= {
        pubkey => $joiner,
        roles  => [],
      };
      delete $invites{$code};
      next;
    }

    if ($kind == 9022) {
      my %tags = _first_tag_values($event->tags);
      my $leaver = $tags{overnet_actor};
      next unless defined $leaver && $leaver =~ /\A[0-9a-f]{64}\z/;
      delete $members{$leaver};
      next;
    }
  }

  return {
    closed     => $closed,
    ban_masks  => [ @ban_masks ],
    members    => \%members,
    invites    => \%invites,
    tombstoned => $tombstoned ? 1 : 0,
  };
}

sub _actor_membership_state {
  my (%args) = @_;
  my $relay = $args{relay};
  my $group_id = $args{group_id};
  my $actor = $args{actor};
  return 0 unless defined $actor && $actor =~ /\A[0-9a-f]{64}\z/;

  my $closed = 0;
  my $member = 0;
  my %invites;
  my $tombstoned = 0;

  for my $event (_group_events($relay, $group_id)) {
    my $kind = $event->kind;

    if ($kind == 39000 || $kind == 9002) {
      my %metadata = _metadata_from_tags($event->tags);
      $closed = $metadata{closed} ? 1 : 0;
      $tombstoned = $metadata{tombstoned} ? 1 : 0;
      %invites = ()
        if $tombstoned;
      next;
    }

    if ($kind == 39002) {
      my $member_info = Net::Nostr::Group->members_from_event($event);
      my %snapshot = map { $_ => 1 } @{$member_info->{members} || []};
      $member = $snapshot{$actor} ? 1 : 0;
      next;
    }

    if ($kind == 9009) {
      my ($code, $target_pubkey) = _invite_from_tags($event->tags);
      next unless defined $code;
      $invites{$code} = {
        (defined $target_pubkey ? (target_pubkey => $target_pubkey) : ()),
      };
      next;
    }

    if ($kind == 9000) {
      my ($target_pubkey) = _target_and_roles_from_put_user($event->tags);
      $member = 1
        if defined $target_pubkey && $target_pubkey eq $actor;
      next;
    }

    if ($kind == 9001) {
      my $target_pubkey = _target_pubkey_from_tags($event->tags);
      $member = 0
        if defined $target_pubkey && $target_pubkey eq $actor;
      next;
    }

    if ($kind == 9021) {
      my %tags = _first_tag_values($event->tags);
      next unless defined $tags{overnet_actor} && $tags{overnet_actor} eq $actor;
      if (!$closed) {
        $member = 1;
        next;
      }

      my $code = $tags{code};
      next unless defined $code && exists $invites{$code};
      my $invite = $invites{$code};
      next if defined $invite->{target_pubkey}
        && $invite->{target_pubkey} ne $actor;

      $member = 1;
      delete $invites{$code};
      next;
    }

    if ($kind == 9022) {
      my %tags = _first_tag_values($event->tags);
      $member = 0
        if defined $tags{overnet_actor} && $tags{overnet_actor} eq $actor;
      next;
    }
  }

  return 0 if $tombstoned;
  return $member;
}

sub _group_events {
  my ($relay, $group_id) = @_;
  my @events;

  for my $event (@{$relay->store->all_events || []}) {
    my $kind = $event->kind;
    next unless $kind == 39000
      || $kind == 39001
      || $kind == 39002
      || $kind == 9000
      || $kind == 9001
      || $kind == 9002
      || $kind == 9009
      || $kind == 9021
      || $kind == 9022;

    my %tags = _first_tag_values($event->tags);
    next unless (defined $tags{d} && $tags{d} eq $group_id)
      || (defined $tags{h} && $tags{h} eq $group_id);

    push @events, $event;
  }

  my @decorated;
  my $index = 0;
  for my $event (@events) {
    push @decorated, [ $index++, $event ];
  }

  return map { $_->[1] } sort {
    ($a->[1]->created_at <=> $b->[1]->created_at)
      || (
        defined _event_sequence_for_sort($a->[1])
          && defined _event_sequence_for_sort($b->[1])
          && ((_event_authority_for_sort($a->[1]) || '') eq (_event_authority_for_sort($b->[1]) || ''))
            ? (_event_sequence_for_sort($a->[1]) <=> _event_sequence_for_sort($b->[1]))
            : (_event_sort_rank($a->[1]) <=> _event_sort_rank($b->[1]))
      )
      || ($a->[0] <=> $b->[0])
  } @decorated;
}

sub _event_authority_for_sort {
  my ($event) = @_;
  my %tags = _first_tag_values($event->tags);
  return $tags{overnet_authority}
    if defined $tags{overnet_authority}
      && !ref($tags{overnet_authority})
      && $tags{overnet_authority} =~ /\A[0-9a-f]{64}\z/;
  return undef;
}

sub _event_sequence_for_sort {
  my ($event) = @_;
  my %tags = _first_tag_values($event->tags);
  return 0 + $tags{overnet_sequence}
    if defined $tags{overnet_sequence}
      && !ref($tags{overnet_sequence})
      && $tags{overnet_sequence} =~ /\A[1-9]\d*\z/;
  return undef;
}

sub _event_sort_rank {
  my ($event) = @_;
  my $kind = $event->kind;
  return 0 if $kind == 39000;
  return 1 if $kind == 39001;
  return 2 if $kind == 39002;
  return 3 if $kind == 39003;
  return 4 if $kind == 9002;
  return 5 if $kind == 9009;
  return 6 if $kind == 9021;
  return 7 if $kind == 9022;
  return 8 if $kind == 9000;
  return 9 if $kind == 9001;
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
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 1;
    $metadata{closed} = 1 if ($tag->[0] || '') eq 'closed';
    $metadata{closed} = 0 if ($tag->[0] || '') eq 'open';
    $metadata{tombstoned} = 1
      if ($tag->[0] || '') eq 'status'
        && @{$tag} >= 2
        && ($tag->[1] || '') eq 'tombstoned';
    push @{$metadata{ban_masks}}, $tag->[1]
      if ($tag->[0] || '') eq 'ban' && @{$tag} >= 2;
  }

  my %seen;
  $metadata{ban_masks} = [
    sort grep {
      defined($_) && !ref($_) && length($_) && !$seen{$_}++
    } @{$metadata{ban_masks}}
  ];
  return %metadata;
}

sub _irc_mask_is_banned {
  my ($ban_masks, $actor_mask) = @_;
  return 0 unless defined $actor_mask && !ref($actor_mask) && length($actor_mask);

  for my $ban_mask (@{$ban_masks || []}) {
    next unless defined $ban_mask && !ref($ban_mask) && length($ban_mask);
    return 1 if Overnet::Authority::HostedChannel::irc_mask_matches(
      mask  => $ban_mask,
      value => $actor_mask,
    );
  }

  return 0;
}

sub _target_and_roles_from_put_user {
  my ($tags) = @_;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || '') eq 'p';
    my $pubkey = $tag->[1];
    next unless defined $pubkey && $pubkey =~ /\A[0-9a-f]{64}\z/;
    return ($pubkey, [ @{$tag}[2 .. $#{$tag}] ]);
  }

  return (undef, []);
}

sub _target_pubkey_from_tags {
  my ($tags) = @_;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2 && ($tag->[0] || '') eq 'p';
    return $tag->[1];
  }

  return undef;
}

sub _invite_from_tags {
  my ($tags) = @_;
  my $code;
  my $target_pubkey;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    $code = $tag->[1]
      if !defined($code) && ($tag->[0] || '') eq 'code';
    $target_pubkey = $tag->[1]
      if !defined($target_pubkey) && ($tag->[0] || '') eq 'p';
  }

  return ($code, $target_pubkey);
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

1;
