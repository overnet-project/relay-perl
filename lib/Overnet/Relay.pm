package Overnet::Relay;

use strict;
use warnings;

use parent 'Net::Nostr::Relay';

use AnyEvent;
use JSON::PP ();
use Socket qw(MSG_PEEK);
use URI::Escape qw(uri_unescape);

use Net::Nostr::Filter;
use Net::Nostr::Message;
use Overnet::Core::Validator ();
use Overnet::Relay::Info;

use Class::Tiny qw(
  name
  description
  banner
  icon
  admin_pubkey
  relay_pubkey
  contact
  software
  version
  terms_of_service
  payments_url
  supported_nips
  retention_seconds
  max_negentropy_sessions
  core_version
  relay_profile
  service_policies
  pricing_url
);

my $JSON = JSON::PP->new->utf8->canonical;
my %VALID_POLICY = map { $_ => 1 } qw(open auth paid closed);
my %VALID_OUTCOME_PREFIX = map { $_ => 1 } qw(
  accepted invalid unauthorized payment_required policy_denied
  not_found unsupported unavailable
);

sub new {
  my ($class, %args) = @_;

  $args{core_version} //= '0.1.0';
  $args{relay_profile} //= 'volunteer-basic';
  $args{max_negentropy_sessions} //= 8;
  $args{supported_nips} = _normalized_supported_nips($args{supported_nips});
  $args{service_policies} = _validated_service_policies($args{service_policies});

  my $self = $class->SUPER::new(%args);
  $self->relay_info($self->_build_relay_info_document);
  return $self;
}

sub _build_relay_info_document {
  my ($self) = @_;

  my $limits = {
    retention_seconds => $self->retention_seconds,
    max_event_bytes => $self->max_message_length // $self->max_content_length // 65536,
    max_filter_limit => $self->max_limit // $self->default_limit // 100,
    max_subscriptions => $self->max_subscriptions // 32,
    max_negentropy_sessions => $self->max_negentropy_sessions,
  };

  my $limitation = {
    max_message_length => $self->max_message_length,
    max_subscriptions => $self->max_subscriptions // 32,
    max_limit => $self->max_limit // $self->default_limit // 100,
    max_content_length => $self->max_content_length,
  };
  $limitation = {
    map { defined $limitation->{$_} ? ($_ => $limitation->{$_}) : () }
      keys %{$limitation}
  };

  return Overnet::Relay::Info->new(
    name => $self->name,
    description => $self->description,
    banner => $self->banner,
    icon => $self->icon,
    pubkey => $self->admin_pubkey,
    self => $self->relay_pubkey,
    contact => $self->contact,
    software => $self->software,
    version => $self->version,
    terms_of_service => $self->terms_of_service,
    payments_url => $self->payments_url,
    supported_nips => $self->supported_nips,
    limitation => $limitation,
    overnet => {
      core_version => $self->core_version,
      relay_profile => $self->relay_profile,
      capabilities => [
        'overnet.events.publish',
        'overnet.events.query',
        'overnet.events.subscribe',
        'overnet.events.sync',
        'overnet.objects.read',
      ],
      limits => $limits,
      service_policies => $self->service_policies,
      (defined $self->pricing_url ? (pricing_url => $self->pricing_url) : ()),
    },
  );
}

sub _handle_nip11_or_ws {
  my ($self, $fh, $peer_host) = @_;
  my $fileno = fileno($fh);
  my $buf = '';
  my ($w, $timer);

  my $cleanup = sub {
    undef $w;
    undef $timer;
    delete $self->_nip11_watchers->{$fileno};
  };

  my $dispatch = sub {
    my $peek = '';
    recv($fh, $peek, 8192, MSG_PEEK);
    my ($method, $path) = $peek =~ /\A([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]\r\n/;

    if (defined $method && $method eq 'OPTIONS') {
      sysread($fh, my $discard, 8192);
      _write_all($fh, Overnet::Relay::Info::cors_preflight_response());
      close $fh;
      $self->_conn_count_by_ip->{$peer_host}--;
      return;
    }

    if (defined $method && defined $path
        && $path =~ m{\A/\.well-known/overnet/v1/object(?:\?|$)}) {
      sysread($fh, my $discard, 8192);
      _write_all($fh, $self->_handle_object_http_request($method, $path));
      close $fh;
      $self->_conn_count_by_ip->{$peer_host}--;
      return;
    }

    if ($peek =~ /Accept:\s*application\/nostr\+json/i
        && $peek !~ /Upgrade:\s*websocket/i) {
      sysread($fh, my $discard, 8192);
      _write_all($fh, $self->relay_info->to_http_response);
      close $fh;
      $self->_conn_count_by_ip->{$peer_host}--;
      return;
    }

    if (defined $method
        && $peek !~ /Upgrade:\s*websocket/i
        && $peek !~ /Accept:\s*application\/nostr\+json/i) {
      sysread($fh, my $discard, 8192);
      _write_all($fh, _http_json_response(
        status_line => 'HTTP/1.1 404 Not Found',
        body => {
          error => {
            code => 'not_found',
            message => 'Unknown HTTP endpoint',
          },
        },
      ));
      close $fh;
      $self->_conn_count_by_ip->{$peer_host}--;
      return;
    }

    $self->_establish_ws($fh, $peer_host);
  };

  $w = AnyEvent->io(fh => $fh, poll => 'r', cb => sub {
    my $chunk = '';
    recv($fh, $chunk, 8192, MSG_PEEK);
    $buf = $chunk;

    if ($buf =~ /\r\n\r\n/ || length($buf) >= 8192) {
      $cleanup->();
      $dispatch->();
    }
  });

  $timer = AnyEvent->timer(after => 5, cb => sub {
    $cleanup->();
    $self->_establish_ws($fh, $peer_host);
  });

  $self->_nip11_watchers->{$fileno} = [$w, $timer];
}

sub _handle_object_http_request {
  my ($self, $method, $path) = @_;

  if ($method ne 'GET') {
    return _http_json_response(
      status_line => 'HTTP/1.1 405 Method Not Allowed',
      body => {
        error => {
          code => 'unsupported',
          message => 'Object read endpoint requires GET',
        },
      },
    );
  }

  my (undef, $query_string) = split /\?/, $path, 2;
  my %query = _decode_query_string($query_string // '');

  my $object_type = $query{type};
  my $object_id = $query{id};

  if (!defined $object_type || ref($object_type) || $object_type eq ''
      || !defined $object_id || ref($object_id) || $object_id eq '') {
    return _http_json_response(
      status_line => 'HTTP/1.1 400 Bad Request',
      body => {
        error => {
          code => 'invalid',
          message => 'type and id query parameters are required',
        },
      },
    );
  }

  my $state_event = $self->_latest_matching_event(
    kinds => [37800],
    object_type => $object_type,
    object_id => $object_id,
  );
  my $removal_event = $self->_latest_matching_event(
    kinds => [7801],
    object_type => $object_type,
    object_id => $object_id,
  );

  if (!$state_event && !$removal_event) {
    return _http_json_response(
      status_line => 'HTTP/1.1 404 Not Found',
      body => {
        error => {
          code => 'not_found',
          message => 'No visible object found for the requested reference',
        },
      },
    );
  }

  return _http_json_response(
    status_line => 'HTTP/1.1 200 OK',
    body => {
      object_type => $object_type,
      object_id => $object_id,
      removed => _object_is_removed($state_event, $removal_event) ? JSON::PP::true : JSON::PP::false,
      state_event => $state_event ? $state_event->to_hash : undef,
      removal_event => $removal_event ? $removal_event->to_hash : undef,
    },
  );
}

sub _latest_matching_event {
  my ($self, %args) = @_;
  my $results = $self->store->query([
    Net::Nostr::Filter->new(
      kinds => $args{kinds},
      '#overnet_ot' => [$args{object_type}],
      '#overnet_oid' => [$args{object_id}],
    ),
  ]);

  return @{$results} ? $results->[0] : undef;
}

sub _handle_event {
  my ($self, $conn_id, $event) = @_;
  my $conn = $self->_connections->{$conn_id};
  my $result = $self->_accept_overnet_event(
    $event,
    conn_id => $conn_id,
    apply_rate_limit => 1,
    require_author_auth => 1,
    broadcast => 1,
  );

  $conn->send(Net::Nostr::Message->new(
    type => 'OK',
    event_id => $result->{event_id},
    accepted => $result->{accepted} ? 1 : 0,
    message => $result->{message},
  )->serialize);
}

sub accept_synced_event {
  my ($self, $event) = @_;

  return $self->_accept_overnet_event(
    $event,
    apply_rate_limit => 0,
    require_author_auth => 0,
    broadcast => 1,
  );
}

sub _accept_overnet_event {
  my ($self, $event, %opts) = @_;

  my $event_id = $event->id // '';
  my $accept = sub {
    my (%extra) = @_;
    return {
      accepted => $extra{accepted},
      stored => $extra{stored} ? 1 : 0,
      event_id => $event_id,
      message => $extra{message},
    };
  };

  my $error = $self->_validate_event($event);
  return $accept->(accepted => 0, stored => 0, message => $error)
    if $error;

  if (defined $self->max_content_length && length($event->content) > $self->max_content_length) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: content too long');
  }

  if (defined $self->max_event_tags && scalar(@{$event->_tags}) > $self->max_event_tags) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: too many tags');
  }

  if (defined $self->created_at_lower_limit
      && $event->created_at < time() - $self->created_at_lower_limit) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: event too old');
  }

  if (defined $self->created_at_upper_limit
      && $event->created_at > time() + $self->created_at_upper_limit) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: event too far in the future');
  }

  my $overnet_error = $self->_validate_overnet_publish($event);
  return $accept->(accepted => 0, stored => 0, message => $overnet_error)
    if $overnet_error;

  if ($self->on_event) {
    my ($ok, $msg) = $self->on_event->($event);
    unless ($ok) {
      return $accept->(
        accepted => 0,
        stored => 0,
        message => _normalize_outcome_message($msg, 'policy_denied', 'rejected by policy'),
      );
    }
  }

  if ($opts{apply_rate_limit}) {
    return $accept->(accepted => 0, stored => 0, message => 'unavailable: rate limited')
      unless $self->_check_rate_limit($opts{conn_id});
  }

  if (defined $self->min_pow_difficulty) {
    my $min = $self->min_pow_difficulty;
    my $committed = $event->committed_target_difficulty;
    return $accept->(
      accepted => 0,
      stored => 0,
      message => "invalid: proof-of-work commitment below required $min",
    ) if !defined($committed) || $committed < $min;

    return $accept->(
      accepted => 0,
      stored => 0,
      message => "invalid: insufficient proof of work (need $min bits)",
    ) if $event->difficulty < $min;
  }

  if ($event->is_expired && !$event->is_ephemeral) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: event has expired');
  }

  if ($opts{require_author_auth} && $event->is_protected) {
    my $authed = $self->_authenticated->{$opts{conn_id}} || {};
    return $accept->(
      accepted => 0,
      stored => 0,
      message => 'unauthorized: protected event requires author authentication',
    ) unless $authed->{$event->pubkey};
  }

  if ($event->kind == 22242) {
    return $accept->(accepted => 0, stored => 0, message => 'invalid: auth events must use AUTH');
  }

  if ($self->store->get_by_id($event->id)) {
    return $accept->(
      accepted => 1,
      stored => 0,
      message => 'accepted: duplicate event already stored',
    );
  }

  if ($event->is_ephemeral) {
    $self->broadcast($event) if $opts{broadcast};
    return $accept->(
      accepted => 1,
      stored => 0,
      message => 'accepted: ephemeral event broadcast',
    );
  }

  if ($event->is_replaceable) {
    my $existing = $self->store->find_replaceable($event->pubkey, $event->kind);
    if ($existing) {
      if (_is_newer_event($event, $existing)) {
        $self->store->delete_by_id($existing->id);
      } else {
        return $accept->(
          accepted => 1,
          stored => 0,
          message => 'accepted: newer replaceable event already stored',
        );
      }
    }
  }

  if ($event->is_addressable) {
    my $existing = $self->store->find_addressable($event->pubkey, $event->kind, $event->d_tag);
    if ($existing) {
      if (_is_newer_event($event, $existing)) {
        $self->store->delete_by_id($existing->id);
      } else {
        return $accept->(
          accepted => 1,
          stored => 0,
          message => 'accepted: newer addressable event already stored',
        );
      }
    }
  }

  $self->store->store($event);
  $self->broadcast($event) if $opts{broadcast};

  return $accept->(
    accepted => 1,
    stored => 1,
    message => 'accepted: stored',
  );
}

sub _handle_req {
  my ($self, $conn_id, $sub_id, @filters) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (defined $self->max_filters && @filters > $self->max_filters) {
    $conn->send(Net::Nostr::Message->new(
      type => 'CLOSED',
      subscription_id => $sub_id,
      message => 'unavailable: too many filters',
    )->serialize);
    return;
  }

  if (defined $self->max_subscriptions) {
    my $existing = $self->_subscriptions->{$conn_id} // {};
    if (!exists $existing->{$sub_id}
        && scalar(keys %{$existing}) >= $self->max_subscriptions) {
      $conn->send(Net::Nostr::Message->new(
        type => 'CLOSED',
        subscription_id => $sub_id,
        message => 'unavailable: too many subscriptions',
      )->serialize);
      return;
    }
  }

  for my $f (@filters) {
    if (defined $self->default_limit && !defined $f->limit) {
      $f->limit($self->default_limit);
    }
    if (defined $self->max_limit
        && (!defined $f->limit || $f->limit > $self->max_limit)) {
      $f->limit($self->max_limit);
    }
  }

  $self->_subscriptions->{$conn_id} //= {};
  my $old_filters = $self->_subscriptions->{$conn_id}{$sub_id};
  $self->_remove_from_sub_index($conn_id, $sub_id, $old_filters) if $old_filters;
  $self->_subscriptions->{$conn_id}{$sub_id} = \@filters;
  $self->_add_to_sub_index($conn_id, $sub_id, \@filters);

  my $results = $self->store->query(\@filters);
  for my $event (@{$results}) {
    $conn->send(Net::Nostr::Message->new(
      type => 'EVENT',
      subscription_id => $sub_id,
      event => $event,
    )->serialize);
  }

  $conn->send(Net::Nostr::Message->new(
    type => 'EOSE',
    subscription_id => $sub_id,
  )->serialize);
}

sub _handle_neg_open {
  my ($self, $conn_id, $msg) = @_;
  my $conn = $self->_connections->{$conn_id};
  my $sub_id = $msg->subscription_id;

  my $sessions = $self->_neg_sessions->{$conn_id} ||= {};
  if (!exists $sessions->{$sub_id}
      && scalar(keys %{$sessions}) >= $self->max_negentropy_sessions) {
    $conn->send(Net::Nostr::Message->new(
      type => 'NEG-ERR',
      subscription_id => $sub_id,
      message => 'unavailable: too many negentropy sessions',
    )->serialize);
    return;
  }

  delete $sessions->{$sub_id};

  my $filter_hash = $msg->filter->to_hash;
  delete $filter_hash->{limit};
  my $unlimited_filter = Net::Nostr::Filter->new(%{$filter_hash});

  my $ne = Net::Nostr::Negentropy->new;
  my $events = $self->store->query([$unlimited_filter]);
  for my $ev (@{$events}) {
    $ne->add_item($ev->created_at, $ev->id);
  }
  $ne->seal;

  my ($response, $have, $need) = eval { $ne->reconcile($msg->neg_msg) };
  if ($@) {
    (my $reason = $@) =~ s/\n\z//;
    $conn->send(Net::Nostr::Message->new(
      type => 'NEG-ERR',
      subscription_id => $sub_id,
      message => "invalid: $reason",
    )->serialize);
    return;
  }

  if (defined $response) {
    $sessions->{$sub_id} = $ne;
    $conn->send(Net::Nostr::Message->new(
      type => 'NEG-MSG',
      subscription_id => $sub_id,
      neg_msg => $response,
    )->serialize);
    return;
  }

  $conn->send(Net::Nostr::Message->new(
    type => 'NEG-MSG',
    subscription_id => $sub_id,
    neg_msg => '61',
  )->serialize);
}

sub _validate_overnet_publish {
  my ($self, $event) = @_;

  my $context = $self->_overnet_validation_context($event);
  my $result = Overnet::Core::Validator::validate($event->to_hash, $context);
  return 'invalid: ' . $result->{reason}
    unless $result->{valid};

  my @mirror_errors = $self->_mirror_tag_errors($event);
  return 'invalid: ' . $mirror_errors[0]
    if @mirror_errors;

  return undef;
}

sub _overnet_validation_context {
  my ($self, $event) = @_;
  my %tag_values = _first_tag_values($event->tags);
  my $context = {};

  if ($event->kind == 7801 && defined $tag_values{e}) {
    my $target_event = $self->store->get_by_id($tag_values{e});
    $context->{target_event} = $target_event->to_hash if $target_event;

    if (defined $tag_values{overnet_delegate}) {
      my $delegation_event = $self->store->get_by_id($tag_values{overnet_delegate});
      $context->{delegation_event} = $delegation_event->to_hash if $delegation_event;
    }
  }

  return $context;
}

sub _mirror_tag_errors {
  my ($self, $event) = @_;
  my %counts;
  my %values;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    $counts{$tag->[0]}++;
    $values{$tag->[0]} = $tag->[1] if !exists $values{$tag->[0]};
  }

  my @errors;
  my %mirror_for = (
    v => 'overnet_v',
    t => 'overnet_et',
    o => 'overnet_ot',
    d => 'overnet_oid',
  );

  for my $mirror (qw(v t o d)) {
    push @errors, "Duplicate $mirror tag"
      if ($counts{$mirror} // 0) > 1;
    push @errors, "Missing required $mirror tag"
      unless defined $values{$mirror};

    my $canonical = $mirror_for{$mirror};
    if (defined $values{$mirror} && defined $values{$canonical}
        && $values{$mirror} ne $values{$canonical}) {
      push @errors, "$mirror tag must match $canonical";
    }
  }

  return @errors;
}

sub _normalized_supported_nips {
  my ($supported_nips) = @_;
  my %seen = map { $_ => 1 } (1, 11, 42, 77);
  if (ref($supported_nips) eq 'ARRAY') {
    $seen{$_} = 1 for @{$supported_nips};
  }
  return [sort { $a <=> $b } keys %seen];
}

sub _validated_service_policies {
  my ($service_policies) = @_;
  my %defaults = (
    publish => 'open',
    query => 'open',
    subscribe => 'open',
    sync => 'open',
    object_read => 'open',
  );

  if (defined $service_policies) {
    die "service_policies must be an object\n"
      unless ref($service_policies) eq 'HASH';
    %defaults = (%defaults, %{$service_policies});
  }

  for my $field (sort keys %defaults) {
    die "Invalid service_policies value for $field\n"
      unless $VALID_POLICY{$defaults{$field}};
  }

  return \%defaults;
}

sub _decode_query_string {
  my ($query_string) = @_;
  my %query;
  return %query unless length $query_string;

  for my $pair (split /&/, $query_string) {
    next unless length $pair;
    my ($key, $value) = split /=/, $pair, 2;
    next unless defined $key;
    $query{uri_unescape($key)} = defined $value ? uri_unescape($value) : '';
  }

  return %query;
}

sub _http_json_response {
  my (%args) = @_;
  my $body = $JSON->encode($args{body});
  return join("\r\n",
    $args{status_line},
    'Content-Type: application/json',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Allow-Headers: Accept',
    'Access-Control-Allow-Methods: GET, OPTIONS',
    'Content-Length: ' . length($body),
  ) . "\r\n\r\n" . $body;
}

sub _write_all {
  my ($fh, $buffer) = @_;
  my $offset = 0;

  while ($offset < length($buffer)) {
    my $written = syswrite($fh, $buffer, length($buffer) - $offset, $offset);
    last unless defined $written && $written > 0;
    $offset += $written;
  }

  return $offset;
}

sub _normalize_outcome_message {
  my ($message, $default_prefix, $default_detail) = @_;
  $default_detail //= '';

  if (defined $message && !ref($message) && $message =~ /\A([a-z_]+):\s/s) {
    return $message if $VALID_OUTCOME_PREFIX{$1};
  }

  my $detail = defined $message && !ref($message) && length($message)
    ? $message
    : $default_detail;

  return $default_prefix . ': ' . $detail;
}

sub _object_is_removed {
  my ($state_event, $removal_event) = @_;
  return 0 unless $removal_event;
  return 1 unless $state_event;
  return _is_newer_event($removal_event, $state_event) ? 1 : 0;
}

sub _is_newer_event {
  my ($new, $existing) = @_;
  return 1 if $new->created_at > $existing->created_at;
  return 1 if $new->created_at == $existing->created_at
           && $new->id lt $existing->id;
  return 0;
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

=head1 NAME

Overnet::Relay - First Overnet relay wrapper on top of Net::Nostr::Relay

=head1 METHODS

=head2 accept_synced_event

  my $result = $relay->accept_synced_event($event);

Validates and ingests an event that arrived through relay-to-relay sync.
This follows the same Overnet event validation and replaceable/addressable
storage semantics as a normal publish, but it skips client-specific publish
controls such as per-connection rate limiting and author-authenticated
protected-event checks.

Returns a hashref containing C<accepted>, C<stored>, C<event_id>, and
C<message>.

=cut
