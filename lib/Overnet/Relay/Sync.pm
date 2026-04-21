package Overnet::Relay::Sync;

use strict;
use warnings;

use AnyEvent;
use Carp qw(croak);

use Class::Tiny qw(
  local_relay
  local_url
  timeout_seconds
);

use Net::Nostr::Client;
use Net::Nostr::Filter;
use Net::Nostr::Negentropy;

sub new {
  my ($class, %args) = @_;
  my %known = map { $_ => 1 } qw(local_relay local_url timeout_seconds);
  my @unknown = grep { !$known{$_} } keys %args;
  croak "unknown argument(s): " . join(', ', sort @unknown)
    if @unknown;

  croak "local_relay or local_url is required"
    unless $args{local_relay} || $args{local_url};
  if ($args{local_relay}) {
    croak "local_relay must support store and accept_synced_event"
      unless $args{local_relay}->can('store')
          && $args{local_relay}->can('accept_synced_event');
  }
  if (defined $args{local_url}) {
    croak "local_url must be a non-empty string"
      if ref($args{local_url}) || $args{local_url} eq '';
  }

  $args{timeout_seconds} //= 5;
  croak "timeout_seconds must be a positive integer"
    unless $args{timeout_seconds} =~ /\A\d+\z/ && $args{timeout_seconds} > 0;

  return bless \%args, $class;
}

sub sync_once {
  my ($self, %args) = @_;
  my %known = map { $_ => 1 } qw(remote_url local_url filter subscription_id);
  my @unknown = grep { !$known{$_} } keys %args;
  croak "unknown argument(s): " . join(', ', sort @unknown)
    if @unknown;

  my $remote_url = $args{remote_url};
  croak "remote_url is required"
    unless defined $remote_url && !ref($remote_url) && length $remote_url;

  my $filter = $args{filter};
  croak "filter is required"
    unless $filter && ref($filter) && $filter->isa('Net::Nostr::Filter');

  my $local_relay = $self->local_relay;
  my $local_url = exists $args{local_url} ? $args{local_url} : $self->local_url;
  croak "sync_once requires local_relay or local_url"
    unless $local_relay || $local_url;
  croak "local_url must be a non-empty string"
    if defined($local_url) && (ref($local_url) || $local_url eq '');

  my $sub_id = defined $args{subscription_id} && length $args{subscription_id}
    ? $args{subscription_id}
    : 'overnet-sync';

  my $neg_filter = _unlimited_filter($filter);
  my $remote_client = Net::Nostr::Client->new;
  my %need;
  my %fetched;
  my @stored_ids;
  my @rejected_ids;
  my $negentropy_rounds = 0;

  eval {
    my $ne = $self->_build_local_negentropy(
      filter => $neg_filter,
      local_relay => $local_relay,
      local_url => $local_url,
      subscription_id => $sub_id,
    );

    $remote_client->connect($remote_url);

    my $neg_done = _callback_waiter(
      timeout_seconds => $self->timeout_seconds,
      error_prefix => 'negentropy sync',
    );

    $remote_client->on(neg_msg => sub {
      my ($reply_sub_id, $neg_msg) = @_;
      return unless $reply_sub_id eq $sub_id;

      $negentropy_rounds++;
      my ($next, $have, $need_ids) = $ne->reconcile($neg_msg);
      $need{$_} = 1 for @{$need_ids || []};

      if (defined $next) {
        $remote_client->neg_msg($sub_id, $next);
        return;
      }

      $remote_client->neg_close($sub_id);
      $neg_done->{cv}->send(1);
    });

    $remote_client->on(neg_err => sub {
      my ($reply_sub_id, $message) = @_;
      return unless $reply_sub_id eq $sub_id;
      $neg_done->{cv}->croak("remote negentropy error: $message");
    });

    $remote_client->neg_open($sub_id, $neg_filter, $ne->initiate);
    _recv_callback_waiter($neg_done);

    my @need_ids = sort keys %need;
    if (@need_ids) {
      %fetched = %{
        $self->_fetch_remote_events(
          client => $remote_client,
          need_ids => \@need_ids,
          subscription_id => $sub_id . '-fetch',
        )
      };

      my $store_result = $self->_store_fetched_events(
        fetched_events => \%fetched,
        requested_ids => \@need_ids,
        local_relay => $local_relay,
        local_url => $local_url,
        subscription_id => $sub_id . '-publish',
      );
      @stored_ids = @{$store_result->{stored_ids}};
      @rejected_ids = @{$store_result->{rejected_ids}};
    }

    1;
  } or do {
    my $error = $@ || 'relay sync failed';
    eval { $remote_client->disconnect if $remote_client->is_connected };
    die $error;
  };

  $remote_client->disconnect if $remote_client->is_connected;

  my @need_ids = sort keys %need;
  my @fetched_ids = sort keys %fetched;
  my %stored = map { $_ => 1 } @stored_ids;
  my @unresolved_ids = grep { !$stored{$_} && !$fetched{$_} } @need_ids;

  return {
    remote_url => $remote_url,
    subscription_id => $sub_id,
    negentropy_rounds => $negentropy_rounds,
    need_ids => \@need_ids,
    fetched_ids => \@fetched_ids,
    stored_ids => \@stored_ids,
    rejected_ids => \@rejected_ids,
    unresolved_ids => \@unresolved_ids,
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

  my $events;
  if ($args{local_relay}) {
    $events = $args{local_relay}->store->query([$args{filter}]);
  } else {
    my $client = Net::Nostr::Client->new;
    my @events;
    my $sub_id = $args{subscription_id} . '-seed';
    eval {
      $client->connect($args{local_url});
      my $done = _callback_waiter(
        timeout_seconds => $self->timeout_seconds,
        error_prefix => 'local seed query',
      );

      $client->on(event => sub {
        my ($reply_sub_id, $event) = @_;
        return unless $reply_sub_id eq $sub_id;
        push @events, $event;
      });

      $client->on(eose => sub {
        my ($reply_sub_id) = @_;
        return unless $reply_sub_id eq $sub_id;
        $done->{cv}->send(1);
      });

      $client->subscribe($sub_id, $args{filter});
      _recv_callback_waiter($done);
      $client->close($sub_id);
      1;
    } or do {
      my $error = $@ || 'local seed query failed';
      eval { $client->disconnect if $client->is_connected };
      die $error;
    };
    $client->disconnect if $client->is_connected;
    $events = \@events;
  }

  for my $event (@{$events}) {
    $ne->add_item($event->created_at, $event->id);
  }
  $ne->seal;

  return $ne;
}

sub _fetch_remote_events {
  my ($self, %args) = @_;
  my %fetched;
  my $done = _callback_waiter(
    timeout_seconds => $self->timeout_seconds,
    error_prefix => 'event fetch',
  );

  $args{client}->on(event => sub {
    my ($reply_sub_id, $event) = @_;
    return unless $reply_sub_id eq $args{subscription_id};
    $fetched{$event->id} = $event;
  });

  $args{client}->on(eose => sub {
    my ($reply_sub_id) = @_;
    return unless $reply_sub_id eq $args{subscription_id};
    $done->{cv}->send(1);
  });

  $args{client}->subscribe(
    $args{subscription_id},
    Net::Nostr::Filter->new(ids => $args{need_ids}),
  );
  _recv_callback_waiter($done);
  $args{client}->close($args{subscription_id});

  return \%fetched;
}

sub _store_fetched_events {
  my ($self, %args) = @_;

  if ($args{local_relay}) {
    my (@stored_ids, @rejected_ids);
    for my $id (@{$args{requested_ids}}) {
      next unless $args{fetched_events}{$id};
      my $result = $args{local_relay}->accept_synced_event($args{fetched_events}{$id});
      if ($result->{accepted} && $result->{stored}) {
        push @stored_ids, $id;
        next;
      }
      push @rejected_ids, $id unless $result->{accepted};
    }
    return {
      stored_ids => \@stored_ids,
      rejected_ids => \@rejected_ids,
    };
  }

  my $client = Net::Nostr::Client->new;
  my %responses;
  my @pending = grep { $args{fetched_events}{$_} } @{$args{requested_ids}};
  return {
    stored_ids => [],
    rejected_ids => [],
  } unless @pending;

  eval {
    $client->connect($args{local_url});
    my $done = _callback_waiter(
      timeout_seconds => $self->timeout_seconds,
      error_prefix => 'local publish',
    );

    $client->on(ok => sub {
      my ($event_id, $accepted, $message) = @_;
      return unless grep { $_ eq $event_id } @pending;
      $responses{$event_id} = {
        accepted => $accepted ? 1 : 0,
        message => $message,
      };
      $done->{cv}->send(1) if scalar(keys %responses) >= scalar(@pending);
    });

    for my $id (@pending) {
      $client->publish($args{fetched_events}{$id});
    }

    _recv_callback_waiter($done);
    1;
  } or do {
    my $error = $@ || 'local publish failed';
    eval { $client->disconnect if $client->is_connected };
    die $error;
  };
  $client->disconnect if $client->is_connected;

  my (@stored_ids, @rejected_ids);
  for my $id (@pending) {
    my $response = $responses{$id} || {};
    if ($response->{accepted} && ($response->{message} || '') eq 'accepted: stored') {
      push @stored_ids, $id;
      next;
    }
    push @rejected_ids, $id unless $response->{accepted};
  }

  return {
    stored_ids => \@stored_ids,
    rejected_ids => \@rejected_ids,
  };
}

sub _callback_waiter {
  my (%args) = @_;
  my $cv = AnyEvent->condvar;
  my $timer;
  $timer = AnyEvent->timer(
    after => $args{timeout_seconds},
    cb => sub {
      undef $timer;
      $cv->croak($args{error_prefix} . " timed out after $args{timeout_seconds} seconds");
    },
  );

  return {
    cv => $cv,
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

=head1 METHODS

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

=cut
