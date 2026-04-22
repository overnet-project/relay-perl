use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib');

use Overnet::Authority::HostedChannel;
use Overnet::Program::IRC::Authority::Coordinator;

{
  package Local::RecoveryCoordinatorServer;

  sub new {
    return bless {
      config => {
        network => 'irc.example.test',
      },
      authoritative_discovered_channels => {},
      authoritative_discovery_event_cache => {},
      authoritative_channel_cache => {},
      _subscriptions => {},
      _source_channel_events => {},
    }, shift;
  }

  sub set_channel_events {
    my ($self, $channel, $events) = @_;
    $self->{_source_channel_events}{$channel} = [ @{$events || []} ];
    return 1;
  }

  sub _authority_relay_enabled { return 1 }
  sub _authority_profile { return 'nip29' }
  sub _authority_relay_url { return 'wss://relay.example.test' }
  sub _authority_relay_query_timeout_ms { return 1500 }
  sub _authority_grant_kind { return 14142 }

  sub _request {
    my ($self, %args) = @_;
    my $method = $args{method};
    my $params = $args{params} || {};

    if ($method eq 'nostr.open_subscription') {
      $self->{_subscriptions}{$params->{subscription_id}} = $params->{filters};
      return {
        subscription_id => $params->{subscription_id},
        events => [],
      };
    }

    if ($method eq 'nostr.read_subscription_snapshot') {
      my $filters = $self->{_subscriptions}{$params->{subscription_id}} || [];
      return {
        events => $self->_events_for_filters($filters),
      };
    }

    if ($method eq 'nostr.query_events') {
      return {
        events => $self->_events_for_filters($params->{filters}),
      };
    }

    return {};
  }

  sub _events_for_filters {
    my ($self, $filters) = @_;
    my @events;
    my %seen_ids;

    for my $channel (sort keys %{$self->{_source_channel_events} || {}}) {
      for my $event (@{$self->{_source_channel_events}{$channel} || []}) {
        next unless ref($event) eq 'HASH';
        next unless $self->_event_matches_any_filter($event, $filters);
        next if defined($event->{id}) && $seen_ids{$event->{id}}++;
        push @events, $event;
      }
    }

    return $self->_sort_authoritative_events(\@events);
  }

  sub _event_matches_any_filter {
    my ($self, $event, $filters) = @_;
    for my $filter (@{$filters || []}) {
      next unless ref($filter) eq 'HASH';
      return 1 if $self->_event_matches_filter($event, $filter);
    }
    return 0;
  }

  sub _event_matches_filter {
    my ($self, $event, $filter) = @_;
    if (ref($filter->{kinds}) eq 'ARRAY' && @{$filter->{kinds}}) {
      return 0 unless grep { ($_ || 0) == ($event->{kind} || 0) } @{$filter->{kinds}};
    }

    for my $key (keys %{$filter}) {
      next unless $key =~ /\A#(.+)\z/;
      my $tag_name = $1;
      my %allowed = map { $_ => 1 } @{$filter->{$key} || []};
      my $matched = 0;
      for my $tag (@{$event->{tags} || []}) {
        next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
        next unless ($tag->[0] || '') eq $tag_name;
        if ($allowed{$tag->[1]}) {
          $matched = 1;
          last;
        }
      }
      return 0 unless $matched;
    }

    return 1;
  }

  sub _authoritative_group_binding {
    my ($self, $channel) = @_;
    my (undef, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
      network        => $self->{config}{network},
      session_config => {
        group_host => 'groups.example.test',
      },
      target => $channel,
    );
    die $error if defined $error;
    return ('groups.example.test', $group_id);
  }

  sub _canonical_channel_name {
    return $_[1];
  }

  sub _is_authoritative_channel {
    return defined($_[1]) && !ref($_[1]) && $_[1] =~ /\A#/;
  }

  sub _sort_authoritative_events {
    my ($self, $events) = @_;
    return [
      sort {
        ($a->{created_at} || 0) <=> ($b->{created_at} || 0)
          || (($a->{id} || '') cmp ($b->{id} || ''))
      } @{$events || []}
    ];
  }

  sub _first_tag_values {
    my ($self, $tags) = @_;
    my %values;
    for my $tag (@{$tags || []}) {
      next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
      next if exists $values{$tag->[0]};
      $values{$tag->[0]} = $tag->[1];
    }
    return %values;
  }

  sub _derive_authoritative_channel_view_from_events {
    my ($self, $channel, $events) = @_;
    my @event_ids = map { $_->{id} } grep { ref($_) eq 'HASH' } @{$events || []};
    my $topic;
    my $tombstoned = 0;

    for my $event (@{$events || []}) {
      next unless ref($event) eq 'HASH';
      my %tags = $self->_first_tag_values($event->{tags});
      $topic = $tags{topic} if defined $tags{topic};
      $tombstoned = ($tags{status} || '') eq 'tombstoned' ? 1 : 0;
    }

    return {
      channel_name => $channel,
      event_ids    => \@event_ids,
      (defined($topic) ? (topic => $topic) : ()),
      ($tombstoned ? (tombstoned => 1) : ()),
    };
  }

  sub _authoritative_channel_state_from_view {
    my ($self, $view) = @_;
    return {
      event_ids => [ @{$view->{event_ids} || []} ],
      (defined($view->{topic}) ? (topic => $view->{topic}) : ()),
      ($view->{tombstoned} ? (tombstoned => 1) : ()),
    };
  }

  sub _sync_authoritative_topic_state_from_view { return 1 }
}

sub _group_id_for {
  my ($channel) = @_;
  my (undef, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => 'irc.example.test',
    session_config => {
      group_host => 'groups.example.test',
    },
    target => $channel,
  );
  die $error if defined $error;
  return $group_id;
}

sub _metadata_event {
  my (%args) = @_;
  return {
    id         => $args{id},
    kind       => $args{kind} || 39000,
    created_at => $args{created_at},
    tags       => [
      [ (($args{kind} || 39000) == 39000 ? 'd' : 'h'), $args{group_id} ],
      (defined($args{topic}) ? ([ 'topic', $args{topic} ]) : ()),
      ($args{tombstoned} ? ([ 'status', 'tombstoned' ]) : ()),
    ],
  };
}

sub _put_user_event {
  my (%args) = @_;
  return {
    id         => $args{id},
    kind       => 9000,
    created_at => $args{created_at},
    tags       => [
      [ 'h', $args{group_id} ],
      [ 'p', $args{target_pubkey} ],
    ],
  };
}

subtest 'refresh preserves cached authoritative events across stale relay snapshots and merges new events after reconnect' => sub {
  my $server = Local::RecoveryCoordinatorServer->new;

  $server->set_channel_events('#ops', [
    _metadata_event(
      id         => 'm1',
      created_at => 1,
      group_id   => _group_id_for('#ops'),
      topic      => 'Old topic',
    ),
    _put_user_event(
      id            => 'u1',
      created_at    => 2,
      group_id      => _group_id_for('#ops'),
      target_pubkey => ('a' x 64),
    ),
  ]);

  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_nip29_channel_cache(
    $server,
    '#ops',
    refresh => 1,
  );
  is_deeply(
    $server->{authoritative_channel_cache}{'#ops'}{view}{event_ids},
    [ 'm1', 'u1' ],
    'initial refresh seeds the cached event history',
  );

  $server->set_channel_events('#ops', []);
  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_nip29_channel_cache(
    $server,
    '#ops',
    refresh => 1,
  );
  is_deeply(
    $server->{authoritative_channel_cache}{'#ops'}{view}{event_ids},
    [ 'm1', 'u1' ],
    'stale empty relay refresh does not erase cached events',
  );

  $server->set_channel_events('#ops', [
    _metadata_event(
      id         => 'm1',
      created_at => 1,
      group_id   => _group_id_for('#ops'),
      topic      => 'Old topic',
    ),
    _metadata_event(
      id         => 'm2',
      kind       => 9002,
      created_at => 3,
      group_id   => _group_id_for('#ops'),
      topic      => 'New topic',
    ),
  ]);
  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_nip29_channel_cache(
    $server,
    '#ops',
    refresh => 1,
  );
  is_deeply(
    $server->{authoritative_channel_cache}{'#ops'}{view}{event_ids},
    [ 'm1', 'u1', 'm2' ],
    'reconnect refresh merges newly seen events with the cached history',
  );
  is(
    $server->{authoritative_channel_cache}{'#ops'}{view}{topic},
    'New topic',
    'reconnect refresh updates derived topic state from the merged history',
  );
};

subtest 'out-of-order discovery replay keeps tombstones authoritative' => sub {
  my $server = Local::RecoveryCoordinatorServer->new;
  my $subscription_id = Overnet::Program::IRC::Authority::Coordinator::authoritative_discovery_subscription_id($server);
  $server->{authoritative_discovery_subscription_id} = $subscription_id;

  Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event(
    $server,
    {
      subscription_id => $subscription_id,
      item_type       => 'nostr.event',
      data            => _metadata_event(
        id         => 't2',
        kind       => 9002,
        created_at => 2,
        group_id   => _group_id_for('#graveyard'),
        tombstoned => 1,
      ),
    },
  );
  Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event(
    $server,
    {
      subscription_id => $subscription_id,
      item_type       => 'nostr.event',
      data            => _metadata_event(
        id         => 't1',
        created_at => 1,
        group_id   => _group_id_for('#graveyard'),
        topic      => 'Dead room',
      ),
    },
  );

  ok(
    !exists($server->{authoritative_discovered_channels}{'#graveyard'}),
    'an older discovery metadata replay does not resurrect a tombstoned hosted channel',
  );
};

subtest 'restart recovery rebuilds discovered channels from relay snapshots' => sub {
  my $server = Local::RecoveryCoordinatorServer->new;
  $server->set_channel_events('#ops', [
    _metadata_event(
      id         => 'm1',
      created_at => 1,
      group_id   => _group_id_for('#ops'),
      topic      => 'Ops room',
    ),
  ]);

  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_discovery_cache(
    $server,
    refresh => 1,
  );
  ok(
    exists($server->{authoritative_discovered_channels}{'#ops'}),
    'discovery cache is populated before restart',
  );

  delete $server->{authoritative_discovered_channels};
  delete $server->{authoritative_discovery_event_cache};
  delete $server->{authoritative_discovery_subscription_id};
  $server->{_subscriptions} = {};

  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_discovery_cache(
    $server,
    refresh => 1,
  );
  ok(
    exists($server->{authoritative_discovered_channels}{'#ops'}),
    'restart recovery rebuilds discovery state from the relay snapshot',
  );
};

done_testing;
