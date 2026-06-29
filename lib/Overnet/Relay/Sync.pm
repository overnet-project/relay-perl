package Overnet::Relay::Sync;

use strictures 2;

use AnyEvent;
use Carp    qw(croak);
use English qw(-no_match_vars);

use Class::Tiny qw(
  local_relay
  local_url
  timeout_seconds
);

use Net::Nostr::Client;
use Net::Nostr::Filter;
use Net::Nostr::Negentropy;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my %known   = map  { $_ => 1 } qw(local_relay local_url timeout_seconds);
  my @unknown = grep { !$known{$_} } keys %args;
  if (@unknown) {
    croak 'unknown argument(s): ' . join ', ', sort @unknown;
  }

  if (!($args{local_relay} || $args{local_url})) {
    croak 'local_relay or local_url is required';
  }
  if ($args{local_relay}) {
    if (!($args{local_relay}->can('store') && $args{local_relay}->can('accept_synced_event'))) {
      croak 'local_relay must support store and accept_synced_event';
    }
  }
  if (defined $args{local_url}) {
    if (ref($args{local_url}) || $args{local_url} eq q{}) {
      croak 'local_url must be a non-empty string';
    }
  }

  $args{timeout_seconds} //= 5;
  if ($args{timeout_seconds} !~ /\A\d+\z/mxs || $args{timeout_seconds} <= 0) {
    croak 'timeout_seconds must be a positive integer';
  }

  return bless \%args, $class;
}

sub sync_once {
  my ($self, %args) = @_;
  my $request       = $self->_sync_request(%args);
  my $remote_client = Net::Nostr::Client->new;
  my $state         = {
    need              => {},
    fetched           => {},
    stored_ids        => [],
    rejected_ids      => [],
    negentropy_rounds => 0,
  };

  my $synced = eval {
    $self->_run_sync_once(
      client  => $remote_client,
      request => $request,
      state   => $state,
    );
    1;
  };
  if (!$synced) {
    my $error = $EVAL_ERROR || 'relay sync failed';
    _disconnect_client_quietly($remote_client);
    croak $error;
  }

  _disconnect_client($remote_client);

  return _sync_result($request, $state);
}

sub _sync_request {
  my ($self, %args) = @_;
  my %known   = map  { $_ => 1 } qw(remote_url local_url filter subscription_id);
  my @unknown = grep { !$known{$_} } keys %args;
  if (@unknown) {
    croak 'unknown argument(s): ' . join ', ', sort @unknown;
  }

  my $remote_url = _required_non_empty_string($args{remote_url}, 'remote_url');

  my $filter = $args{filter};
  if (!($filter && ref($filter) && $filter->isa('Net::Nostr::Filter'))) {
    croak 'filter is required';
  }

  my $local_relay = $self->local_relay;
  my $local_url   = exists $args{local_url} ? $args{local_url} : $self->local_url;
  if (!($local_relay || $local_url)) {
    croak 'sync_once requires local_relay or local_url';
  }
  if (defined($local_url) && (ref($local_url) || $local_url eq q{})) {
    croak 'local_url must be a non-empty string';
  }

  my $sub_id =
    defined $args{subscription_id} && length $args{subscription_id}
    ? $args{subscription_id}
    : 'overnet-sync';

  return {
    remote_url      => $remote_url,
    local_relay     => $local_relay,
    local_url       => $local_url,
    filter          => $filter,
    neg_filter      => _unlimited_filter($filter),
    subscription_id => $sub_id,
  };
}

sub _required_non_empty_string {
  my ($value, $label) = @_;
  if (!(defined $value && !ref($value) && length $value)) {
    croak "$label is required";
  }

  return $value;
}

sub _run_sync_once {
  my ($self, %args) = @_;
  my $client  = $args{client};
  my $request = $args{request};
  my $state   = $args{state};

  my $ne = $self->_build_local_negentropy(
    filter          => $request->{neg_filter},
    local_relay     => $request->{local_relay},
    local_url       => $request->{local_url},
    subscription_id => $request->{subscription_id},
  );

  $client->connect($request->{remote_url});
  $self->_negotiate_remote(
    client  => $client,
    request => $request,
    state   => $state,
    ne      => $ne,
  );
  $self->_fetch_and_store_needed_events(
    client  => $client,
    request => $request,
    state   => $state,
  );

  return 1;
}

sub _negotiate_remote {
  my ($self, %args) = @_;
  my $client = $args{client};
  my $sub_id = $args{request}{subscription_id};
  my $state  = $args{state};
  my $ne     = $args{ne};

  my $neg_done = _callback_waiter(
    timeout_seconds => $self->timeout_seconds,
    error_prefix    => 'negentropy sync',
  );

  $client->on(
    neg_msg => sub {
      my ($reply_sub_id, $neg_msg) = @_;
      if ($reply_sub_id ne $sub_id) {
        return;
      }

      $state->{negentropy_rounds}++;
      my ($next, $have, $need_ids) = $ne->reconcile($neg_msg);
      for my $id (@{$need_ids || []}) {
        $state->{need}{$id} = 1;
      }

      if (defined $next) {
        $client->neg_msg($sub_id, $next);
        return;
      }

      $client->neg_close($sub_id);
      $neg_done->{cv}->send(1);
    }
  );

  $client->on(
    neg_err => sub {
      my ($reply_sub_id, $message) = @_;
      if ($reply_sub_id ne $sub_id) {
        return;
      }
      $neg_done->{cv}->croak("remote negentropy error: $message");
    }
  );

  $client->neg_open($sub_id, $args{request}{neg_filter}, $ne->initiate);
  _recv_callback_waiter($neg_done);

  return 1;
}

sub _fetch_and_store_needed_events {
  my ($self, %args) = @_;
  my @need_ids = sort keys %{$args{state}{need}};
  if (!@need_ids) {
    return 1;
  }

  my $sub_id  = $args{request}{subscription_id};
  my $fetched = $self->_fetch_remote_events(
    client          => $args{client},
    need_ids        => \@need_ids,
    subscription_id => $sub_id . '-fetch',
  );
  $args{state}{fetched} = $fetched;

  my $store_result = $self->_store_fetched_events(
    fetched_events  => $fetched,
    requested_ids   => \@need_ids,
    local_relay     => $args{request}{local_relay},
    local_url       => $args{request}{local_url},
    subscription_id => $sub_id . '-publish',
  );
  $args{state}{stored_ids}   = $store_result->{stored_ids};
  $args{state}{rejected_ids} = $store_result->{rejected_ids};

  return 1;
}

sub _sync_result {
  my ($request, $state) = @_;
  my @need_ids       = sort keys %{$state->{need}};
  my @fetched_ids    = sort keys %{$state->{fetched}};
  my %stored         = map { $_ => 1 } @{$state->{stored_ids}};
  my %fetched        = %{$state->{fetched}};
  my @unresolved_ids = grep { !$stored{$_} && !$fetched{$_} } @need_ids;

  return {
    remote_url        => $request->{remote_url},
    subscription_id   => $request->{subscription_id},
    negentropy_rounds => $state->{negentropy_rounds},
    need_ids          => \@need_ids,
    fetched_ids       => \@fetched_ids,
    stored_ids        => $state->{stored_ids},
    rejected_ids      => $state->{rejected_ids},
    unresolved_ids    => \@unresolved_ids,
  };
}

sub _unlimited_filter {
  my ($filter) = @_;
  my $filter_hash = $filter->to_hash;
  delete $filter_hash->{limit};
  return Net::Nostr::Filter->new(%{$filter_hash});
}

sub _build_local_negentropy {
  my ($self, %args) = @_;
  my $ne = Net::Nostr::Negentropy->new;

  my $events =
      $args{local_relay}
    ? $args{local_relay}->store->query([$args{filter}])
    : $self->_query_local_events_from_url(%args);

  for my $event (@{$events}) {
    $ne->add_item($event->created_at, $event->id);
  }
  $ne->seal;

  return $ne;
}

sub _query_local_events_from_url {
  my ($self, %args) = @_;
  my $client = Net::Nostr::Client->new;
  my @events;
  my $sub_id = $args{subscription_id} . '-seed';

  my $queried = eval {
    $client->connect($args{local_url});
    $self->_collect_local_seed_events(
      client          => $client,
      events          => \@events,
      filter          => $args{filter},
      subscription_id => $sub_id,
    );
    1;
  };
  if (!$queried) {
    my $error = $EVAL_ERROR || 'local seed query failed';
    _disconnect_client_quietly($client);
    croak $error;
  }
  _disconnect_client($client);

  return \@events;
}

sub _collect_local_seed_events {
  my ($self, %args) = @_;
  my $done = _callback_waiter(
    timeout_seconds => $self->timeout_seconds,
    error_prefix    => 'local seed query',
  );

  $args{client}->on(
    event => sub {
      my ($reply_sub_id, $event) = @_;
      if ($reply_sub_id ne $args{subscription_id}) {
        return;
      }
      push @{$args{events}}, $event;
    }
  );

  $args{client}->on(
    eose => sub {
      my ($reply_sub_id) = @_;
      if ($reply_sub_id ne $args{subscription_id}) {
        return;
      }
      $done->{cv}->send(1);
    }
  );

  $args{client}->subscribe($args{subscription_id}, $args{filter});
  _recv_callback_waiter($done);
  $args{client}->close($args{subscription_id});

  return 1;
}

sub _fetch_remote_events {
  my ($self, %args) = @_;
  my %fetched;
  my $done = _callback_waiter(
    timeout_seconds => $self->timeout_seconds,
    error_prefix    => 'event fetch',
  );

  $args{client}->on(
    event => sub {
      my ($reply_sub_id, $event) = @_;
      if ($reply_sub_id ne $args{subscription_id}) {
        return;
      }
      $fetched{$event->id} = $event;
    }
  );

  $args{client}->on(
    eose => sub {
      my ($reply_sub_id) = @_;
      if ($reply_sub_id ne $args{subscription_id}) {
        return;
      }
      $done->{cv}->send(1);
    }
  );

  $args{client}->subscribe($args{subscription_id}, Net::Nostr::Filter->new(ids => $args{need_ids}),);
  _recv_callback_waiter($done);
  $args{client}->close($args{subscription_id});

  return \%fetched;
}

sub _store_fetched_events {
  my ($self, %args) = @_;

  if ($args{local_relay}) {
    return _store_fetched_events_in_relay(%args);
  }

  return $self->_publish_fetched_events_to_url(%args);
}

sub _store_fetched_events_in_relay {
  my (%args) = @_;
  my (@stored_ids, @rejected_ids);
  for my $id (@{$args{requested_ids}}) {
    if (!$args{fetched_events}{$id}) {
      next;
    }
    my $result = $args{local_relay}->accept_synced_event($args{fetched_events}{$id});
    if ($result->{accepted} && $result->{stored}) {
      push @stored_ids, $id;
      next;
    }
    if (!$result->{accepted}) {
      push @rejected_ids, $id;
    }
  }

  return {
    stored_ids   => \@stored_ids,
    rejected_ids => \@rejected_ids,
  };
}

sub _publish_fetched_events_to_url {
  my ($self, %args) = @_;
  my $client = Net::Nostr::Client->new;
  my %responses;
  my @pending = grep { $args{fetched_events}{$_} } @{$args{requested_ids}};
  my %pending = map  { $_ => 1 } @pending;

  if (!@pending) {
    return {
      stored_ids   => [],
      rejected_ids => [],
    };
  }

  my $published = eval {
    $client->connect($args{local_url});
    my $done = _callback_waiter(
      timeout_seconds => $self->timeout_seconds,
      error_prefix    => 'local publish',
    );

    $client->on(
      ok => sub {
        my ($event_id, $accepted, $message) = @_;
        if (!$pending{$event_id}) {
          return;
        }
        $responses{$event_id} = {
          accepted => $accepted ? 1 : 0,
          message  => $message,
        };
        if (scalar(keys %responses) >= scalar @pending) {
          $done->{cv}->send(1);
        }
      }
    );

    for my $id (@pending) {
      $client->publish($args{fetched_events}{$id});
    }

    _recv_callback_waiter($done);
    1;
  };
  if (!$published) {
    my $error = $EVAL_ERROR || 'local publish failed';
    _disconnect_client_quietly($client);
    croak $error;
  }
  _disconnect_client($client);

  my (@stored_ids, @rejected_ids);
  for my $id (@pending) {
    my $response = $responses{$id} || {};
    if ($response->{accepted} && ($response->{message} || q{}) eq 'accepted: stored') {
      push @stored_ids, $id;
      next;
    }
    if (!$response->{accepted}) {
      push @rejected_ids, $id;
    }
  }

  return {
    stored_ids   => \@stored_ids,
    rejected_ids => \@rejected_ids,
  };
}

sub _disconnect_client {
  my ($client) = @_;
  if ($client->is_connected) {
    $client->disconnect;
  }

  return 1;
}

sub _disconnect_client_quietly {
  my ($client) = @_;
  my $disconnected = eval {
    _disconnect_client($client);
    1;
  };

  return $disconnected ? 1 : 0;
}

sub _callback_waiter {
  my (%args) = @_;
  my $cv = AnyEvent->condvar;
  my $timer;
  $timer = AnyEvent->timer(
    after => $args{timeout_seconds},
    cb    => sub {
      undef $timer;
      $cv->croak($args{error_prefix} . " timed out after $args{timeout_seconds} seconds");
    },
  );

  return {
    cv    => $cv,
    timer => \$timer,
  };
}

sub _recv_callback_waiter {
  my ($waiter) = @_;
  my $result = $waiter->{cv}->recv;
  ${$waiter->{timer}} = undef;
  return $result;
}

1;

=head1 NAME

Overnet::Relay::Sync - One-shot relay-to-relay Overnet sync via NIP-77

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Relay::Sync;
  use Net::Nostr::Filter;

  my $sync = Overnet::Relay::Sync->new(local_relay => $relay);
  my $result = $sync->sync_once(
    remote_url => 'ws://127.0.0.1:7447',
    local_url => 'ws://127.0.0.1:7448',
    filter => Net::Nostr::Filter->new(
      kinds => [37800],
      '#t'  => ['chat.topic'],
      '#o'  => ['chat.channel'],
      '#d'  => ['irc:local:#overnet'],
    ),
  );

=head1 DESCRIPTION

Performs one relay-to-relay synchronization pass against a remote relay.
The sync uses NIP-77 negentropy with the provided filter to determine
which event IDs the remote relay has that the local relay lacks, then
issues a one-shot REQ by event ID to fetch and ingest those events.

The local side may be provided either as an in-process C<local_relay>
object or as a live relay URL in C<local_url>. When C<local_url> is used,
the sync helper seeds the local negentropy set via a one-shot REQ and
publishes fetched events back into the local relay over WebSocket.

=head1 SUBROUTINES/METHODS

=head2 new

  my $sync = Overnet::Relay::Sync->new(
    local_relay => $relay,
    local_url => 'ws://127.0.0.1:7448',
    timeout_seconds => 5,
  );

Creates a sync helper bound to either a local L<Overnet::Relay> instance,
or a local relay WebSocket URL, or both.

=head2 sync_once

  my $result = $sync->sync_once(
    remote_url => 'ws://127.0.0.1:7447',
    local_url => 'ws://127.0.0.1:7448',
    filter => $filter,
    subscription_id => 'overnet-sync',
  );

Runs a single negentropy reconciliation plus fetch pass and returns a hashref
containing the negotiated C<need_ids>, fetched IDs, stored IDs, and any
unresolved or rejected IDs.

=head2 local_relay

Returns the in-process local relay, when configured.

=head2 local_url

Returns the local relay URL, when configured.

=head2 timeout_seconds

Returns the callback timeout used for WebSocket operations.

=head1 DIAGNOSTICS

Invalid arguments, timeout failures, and relay sync failures are reported with
C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

The caller provides relay URLs, filters, and optional timeout values.

=head1 DEPENDENCIES

Requires L<AnyEvent>, L<Class::Tiny>, and L<Net::Nostr>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
