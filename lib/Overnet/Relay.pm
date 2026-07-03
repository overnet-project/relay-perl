package Overnet::Relay;

use strictures 2;
use Moo;

use AnyEvent;
use Carp        qw(croak);
use English     qw(-no_match_vars);
use JSON        ();
use Socket      qw(MSG_PEEK);
use URI::Escape qw(uri_unescape);

use Net::Nostr::Filter;
use Net::Nostr::Message;
use Overnet::Core::Validator ();
use Overnet::Relay::Info;
use Overnet::Relay::ProfileContracts;

extends 'Net::Nostr::Relay';

our $VERSION = '0.001';

my $JSON                 = JSON->new->utf8->canonical;
my %VALID_POLICY         = map { $_ => 1 } qw(open auth paid closed);
my %VALID_OUTCOME_PREFIX = map { $_ => 1 } qw(
  accepted invalid unauthorized payment_required policy_denied
  not_found unsupported unavailable
);
my @DEFAULT_SUPPORTED_NIPS = (1, 11, 42, 77);

my @OVERNET_RELAY_FIELDS = qw(
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
  profile_contract_policy
  profile_contracts
  _profile_contract_index
  service_policies
  pricing_url
);

has name                    => (is => 'rw');
has description             => (is => 'rw');
has banner                  => (is => 'rw');
has icon                    => (is => 'rw');
has admin_pubkey            => (is => 'rw');
has relay_pubkey            => (is => 'rw');
has contact                 => (is => 'rw');
has software                => (is => 'rw');
has version                 => (is => 'rw');
has terms_of_service        => (is => 'rw');
has payments_url            => (is => 'rw');
has supported_nips          => (is => 'rw');
has retention_seconds       => (is => 'rw');
has max_negentropy_sessions => (is => 'rw');
has core_version            => (is => 'rw');
has relay_profile           => (is => 'rw');
has profile_contract_policy => (is => 'rw');
has profile_contracts       => (is => 'rw');
has _profile_contract_index => (is => 'rw');
has service_policies        => (is => 'rw');
has pricing_url             => (is => 'rw');

around new => sub {
  my ($orig, $class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my %overnet_args;
  for my $field (@OVERNET_RELAY_FIELDS) {
    if (exists $args{$field}) {
      $overnet_args{$field} = delete $args{$field};
    }
  }

  $overnet_args{core_version}            //= '0.1.0';
  $overnet_args{relay_profile}           //= 'volunteer-basic';
  $overnet_args{max_negentropy_sessions} //= 8;
  $overnet_args{supported_nips}          = _normalized_supported_nips($overnet_args{supported_nips});
  $overnet_args{service_policies}        = _validated_service_policies($overnet_args{service_policies});
  $overnet_args{_profile_contract_index} = Overnet::Relay::ProfileContracts->new(
    contracts => $overnet_args{profile_contracts},
    policy    => $overnet_args{profile_contract_policy},
  );
  $overnet_args{profile_contract_policy} = $overnet_args{_profile_contract_index}->policy;
  $overnet_args{profile_contracts}       = $overnet_args{_profile_contract_index}->contracts;

  my $self = $class->SUPER::new(\%args);
  for my $field (@OVERNET_RELAY_FIELDS) {
    $self->$field($overnet_args{$field});
  }
  $self->relay_info($self->_build_relay_info_document);
  return $self;
};

no Moo;

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub _build_relay_info_document {
  my ($self) = @_;

  my $limits = {
    retention_seconds       => $self->retention_seconds,
    max_event_bytes         => $self->max_message_length // $self->max_content_length // 65_536,
    max_filter_limit        => $self->max_limit          // $self->default_limit      // 100,
    max_subscriptions       => $self->max_subscriptions  // 32,
    max_negentropy_sessions => $self->max_negentropy_sessions,
  };

  my $limitation = {
    max_message_length => $self->max_message_length,
    max_subscriptions  => $self->max_subscriptions // 32,
    max_limit          => $self->max_limit // $self->default_limit // 100,
    max_content_length => $self->max_content_length,
  };
  $limitation = {
    map { defined $limitation->{$_} ? ($_ => $limitation->{$_}) : () }
      keys %{$limitation}
  };
  my $profile_contract_metadata = $self->_profile_contract_index->metadata;

  return Overnet::Relay::Info->new(
    name             => $self->name,
    description      => $self->description,
    banner           => $self->banner,
    icon             => $self->icon,
    pubkey           => $self->admin_pubkey,
    self             => $self->relay_pubkey,
    contact          => $self->contact,
    software         => $self->software,
    version          => $self->version,
    terms_of_service => $self->terms_of_service,
    payments_url     => $self->payments_url,
    supported_nips   => $self->supported_nips,
    limitation       => $limitation,
    overnet          => {
      core_version  => $self->core_version,
      relay_profile => $self->relay_profile,
      capabilities  => [
        'overnet.events.publish', 'overnet.events.query', 'overnet.events.subscribe', 'overnet.events.sync',
        'overnet.objects.read',
      ],
      limits           => $limits,
      service_policies => $self->service_policies,
      (defined $profile_contract_metadata ? (profile_contracts => $profile_contract_metadata) : ()),
      (defined $self->pricing_url         ? (pricing_url       => $self->pricing_url)         : ()),
    },
  );
}

sub _handle_nip11_or_ws {
  my ($self, $fh, $peer_host) = @_;
  my $fileno = fileno($fh);
  my $buf    = q{};
  my ($w, $timer);

  my $cleanup = sub {
    undef $w;
    undef $timer;
    delete $self->_nip11_watchers->{$fileno};
  };

  my $dispatch = sub {
    my $peek = q{};
    recv($fh, $peek, 8_192, MSG_PEEK);
    my ($method, $path) = $peek =~ /\A([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]\r\n/mxs;

    if (defined $method && $method eq 'OPTIONS') {
      sysread($fh, my $discard, 8_192);
      $self->_finish_http_request($fh, $peer_host, Overnet::Relay::Info::cors_preflight_response());
      return;
    }

    if ( defined $method
      && defined $path
      && $path =~ m{\A/\.well-known/overnet/v1/object(?:\?|$)}mxs) {
      sysread($fh, my $discard, 8_192);
      $self->_finish_http_request($fh, $peer_host, $self->_handle_object_http_request($method, $path));
      return;
    }

    if ( $peek =~ /Accept:\s*application\/nostr\+json/imxs
      && $peek !~ /Upgrade:\s*websocket/imxs) {
      sysread($fh, my $discard, 8_192);
      $self->_finish_http_request($fh, $peer_host, $self->relay_info->to_http_response);
      return;
    }

    if ( defined $method
      && $peek !~ /Upgrade:\s*websocket/imxs
      && $peek !~ /Accept:\s*application\/nostr\+json/imxs) {
      sysread($fh, my $discard, 8_192);
      $self->_finish_http_request(
        $fh,
        $peer_host,
        _http_json_response(
          status_line => 'HTTP/1.1 404 Not Found',
          body        => {
            error => {
              code    => 'not_found',
              message => 'Unknown HTTP endpoint',
            },
          },
        )
      );
      return;
    }

    $self->_establish_ws($fh, $peer_host);
  };

  $w = AnyEvent->io(
    fh   => $fh,
    poll => 'r',
    cb   => sub {
      my $chunk = q{};
      recv($fh, $chunk, 8_192, MSG_PEEK);
      $buf = $chunk;

      if ($buf =~ /\r\n\r\n/mxs || length($buf) >= 8_192) {
        $cleanup->();
        $dispatch->();
      }
    }
  );

  $timer = AnyEvent->timer(
    after => 5,
    cb    => sub {
      $cleanup->();
      $self->_establish_ws($fh, $peer_host);
    }
  );

  $self->_nip11_watchers->{$fileno} = [$w, $timer];
  return;
}

sub _finish_http_request {
  my ($self, $fh, $peer_host, $response) = @_;
  _write_all($fh, $response);
  my $closed = close $fh;
  $self->_conn_count_by_ip->{$peer_host}--;
  return $closed ? 1 : 0;
}

sub _handle_object_http_request {
  my ($self, $method, $path) = @_;

  if ($method ne 'GET') {
    return _http_json_response(
      status_line => 'HTTP/1.1 405 Method Not Allowed',
      body        => {
        error => {
          code    => 'unsupported',
          message => 'Object read endpoint requires GET',
        },
      },
    );
  }

  my (undef, $query_string) = split /\?/mxs, $path, 2;
  my %query = _decode_query_string($query_string // q{});

  my $object_type = $query{type};
  my $object_id   = $query{id};

  if (!defined $object_type
    || ref($object_type)
    || $object_type eq q{}
    || !defined $object_id
    || ref($object_id)
    || $object_id eq q{}) {
    return _http_json_response(
      status_line => 'HTTP/1.1 400 Bad Request',
      body        => {
        error => {
          code    => 'invalid',
          message => 'type and id query parameters are required',
        },
      },
    );
  }

  my $state_event = $self->_latest_matching_event(
    kinds       => [37_800],
    object_type => $object_type,
    object_id   => $object_id,
  );
  my $removal_event = $self->_latest_matching_event(
    kinds       => [7_801],
    object_type => $object_type,
    object_id   => $object_id,
  );

  if (!$state_event && !$removal_event) {
    return _http_json_response(
      status_line => 'HTTP/1.1 404 Not Found',
      body        => {
        error => {
          code    => 'not_found',
          message => 'No visible object found for the requested reference',
        },
      },
    );
  }

  return _http_json_response(
    status_line => 'HTTP/1.1 200 OK',
    body        => {
      object_type   => $object_type,
      object_id     => $object_id,
      removed       => _object_is_removed($state_event, $removal_event) ? JSON::true              : JSON::false,
      state_event   => $state_event                                     ? $state_event->to_hash   : undef,
      removal_event => $removal_event                                   ? $removal_event->to_hash : undef,
    },
  );
}

sub _latest_matching_event {
  my ($self, %args) = @_;
  my $results = $self->store->query(
    [
      Net::Nostr::Filter->new(
        kinds          => $args{kinds},
        '#overnet_ot'  => [$args{object_type}],
        '#overnet_oid' => [$args{object_id}],
      ),
    ]
  );

  return @{$results} ? $results->[0] : undef;
}

sub _handle_event {
  my ($self, $conn_id, $event) = @_;
  my $conn   = $self->_connections->{$conn_id};
  my $result = $self->_accept_overnet_event(
    $event,
    conn_id             => $conn_id,
    apply_rate_limit    => 1,
    require_author_auth => 1,
    broadcast           => 1,
  );

  $conn->send(
    Net::Nostr::Message->new(
      type     => 'OK',
      event_id => $result->{event_id},
      accepted => $result->{accepted} ? 1 : 0,
      message  => $result->{message},
    )->serialize
  );
  return;
}

sub accept_synced_event {
  my ($self, $event) = @_;

  return $self->_accept_overnet_event(
    $event,
    apply_rate_limit    => 0,
    require_author_auth => 0,
    broadcast           => 1,
  );
}

sub _accept_overnet_event {
  my ($self, $event, %opts) = @_;

  my $rejection = $self->_pre_store_rejection($event, \%opts);
  if (defined $rejection) {
    return _event_result($event, accepted => 0, stored => 0, message => $rejection);
  }

  my $early_acceptance = $self->_early_acceptance_result($event, \%opts);
  if ($early_acceptance) {
    return $early_acceptance;
  }

  my $replaceable_message = $self->_replaceable_conflict_message($event);
  if (defined $replaceable_message) {
    return _event_result($event, accepted => 1, stored => 0, message => $replaceable_message);
  }

  my $addressable_message = $self->_addressable_conflict_message($event);
  if (defined $addressable_message) {
    return _event_result($event, accepted => 1, stored => 0, message => $addressable_message);
  }

  $self->store->store($event);
  if ($opts{broadcast}) {
    $self->broadcast($event);
  }

  return _event_result($event, accepted => 1, stored => 1, message => 'accepted: stored');
}

sub _event_result {
  my ($event, %extra) = @_;
  return {
    accepted => $extra{accepted},
    stored   => $extra{stored} ? 1 : 0,
    event_id => $event->id // q{},
    message  => $extra{message},
  };
}

sub _pre_store_rejection {
  my ($self, $event, $opts) = @_;

  my $message = $self->_basic_publish_rejection($event);
  if (defined $message) {
    return $message;
  }

  $message = $self->_policy_publish_rejection($event);
  if (defined $message) {
    return $message;
  }

  $message = $self->_rate_limit_rejection($opts);
  if (defined $message) {
    return $message;
  }

  $message = $self->_proof_of_work_rejection($event);
  if (defined $message) {
    return $message;
  }

  if ($event->is_expired && !$event->is_ephemeral) {
    return 'invalid: event has expired';
  }

  $message = $self->_protected_publish_rejection($event, $opts);
  if (defined $message) {
    return $message;
  }

  if ($event->kind == 22_242) {
    return 'invalid: auth events must use AUTH';
  }

  return;
}

sub _basic_publish_rejection {
  my ($self, $event) = @_;

  my $message = $self->_validate_event($event);
  if ($message) {
    return $message;
  }

  if (defined $self->max_content_length && length($event->content) > $self->max_content_length) {
    return 'invalid: content too long';
  }

  if (defined $self->max_event_tags && scalar(@{$event->_tags}) > $self->max_event_tags) {
    return 'invalid: too many tags';
  }

  if (defined $self->created_at_lower_limit
    && $event->created_at < time() - $self->created_at_lower_limit) {
    return 'invalid: event too old';
  }

  if (defined $self->created_at_upper_limit
    && $event->created_at > time() + $self->created_at_upper_limit) {
    return 'invalid: event too far in the future';
  }

  return $self->_validate_overnet_publish($event);
}

sub _policy_publish_rejection {
  my ($self, $event) = @_;
  if (!$self->on_event) {
    return;
  }

  my ($ok, $msg) = $self->on_event->($event);
  if ($ok) {
    return;
  }

  return _normalize_outcome_message($msg, 'policy_denied', 'rejected by policy');
}

sub _rate_limit_rejection {
  my ($self, $opts) = @_;
  if (!$opts->{apply_rate_limit}) {
    return;
  }
  if ($self->_check_rate_limit($opts->{conn_id})) {
    return;
  }

  return 'unavailable: rate limited';
}

sub _proof_of_work_rejection {
  my ($self, $event) = @_;
  if (!defined $self->min_pow_difficulty) {
    return;
  }

  my $min       = $self->min_pow_difficulty;
  my $committed = $event->committed_target_difficulty;
  if (!defined($committed) || $committed < $min) {
    return "invalid: proof-of-work commitment below required $min";
  }
  if ($event->difficulty < $min) {
    return "invalid: insufficient proof of work (need $min bits)";
  }

  return;
}

sub _protected_publish_rejection {
  my ($self, $event, $opts) = @_;
  if (!($opts->{require_author_auth} && $event->is_protected)) {
    return;
  }

  my $authed = $self->_authenticated->{$opts->{conn_id}} || {};
  if ($authed->{$event->pubkey}) {
    return;
  }

  return 'unauthorized: protected event requires author authentication';
}

sub _early_acceptance_result {
  my ($self, $event, $opts) = @_;
  if ($self->store->get_by_id($event->id)) {
    return _event_result(
      $event,
      accepted => 1,
      stored   => 0,
      message  => 'accepted: duplicate event already stored',
    );
  }

  if ($event->is_ephemeral) {
    if ($opts->{broadcast}) {
      $self->broadcast($event);
    }
    return _event_result(
      $event,
      accepted => 1,
      stored   => 0,
      message  => 'accepted: ephemeral event broadcast',
    );
  }

  return;
}

sub _replaceable_conflict_message {
  my ($self, $event) = @_;
  if (!$event->is_replaceable) {
    return;
  }

  my $existing = $self->store->find_replaceable($event->pubkey, $event->kind);
  if (!$existing) {
    return;
  }
  if (_is_newer_event($event, $existing)) {
    $self->store->delete_by_id($existing->id);
    return;
  }

  return 'accepted: newer replaceable event already stored';
}

sub _addressable_conflict_message {
  my ($self, $event) = @_;
  if (!$event->is_addressable) {
    return;
  }

  my $existing = $self->store->find_addressable($event->pubkey, $event->kind, $event->d_tag);
  if (!$existing) {
    return;
  }
  if (_is_newer_event($event, $existing)) {
    $self->store->delete_by_id($existing->id);
    return;
  }

  return 'accepted: newer addressable event already stored';
}

sub _handle_req {
  my ($self, $conn_id, $sub_id, @filters) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (defined $self->max_filters && @filters > $self->max_filters) {
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'CLOSED',
        subscription_id => $sub_id,
        message         => 'unavailable: too many filters',
      )->serialize
    );
    return;
  }

  if (defined $self->max_subscriptions) {
    my $existing = $self->_subscriptions->{$conn_id} // {};
    if (!exists $existing->{$sub_id}
      && scalar(keys %{$existing}) >= $self->max_subscriptions) {
      $conn->send(
        Net::Nostr::Message->new(
          type            => 'CLOSED',
          subscription_id => $sub_id,
          message         => 'unavailable: too many subscriptions',
        )->serialize
      );
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
  if ($old_filters) {
    $self->_remove_from_sub_index($conn_id, $sub_id, $old_filters);
  }
  $self->_subscriptions->{$conn_id}{$sub_id} = \@filters;
  $self->_add_to_sub_index($conn_id, $sub_id, \@filters);

  my $results = $self->store->query(\@filters);
  for my $event (@{$results}) {
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'EVENT',
        subscription_id => $sub_id,
        event           => $event,
      )->serialize
    );
  }

  $conn->send(
    Net::Nostr::Message->new(
      type            => 'EOSE',
      subscription_id => $sub_id,
    )->serialize
  );
  return;
}

sub _handle_neg_open {
  my ($self, $conn_id, $msg) = @_;
  my $conn   = $self->_connections->{$conn_id};
  my $sub_id = $msg->subscription_id;

  my $sessions = $self->_neg_sessions->{$conn_id} ||= {};
  if (!exists $sessions->{$sub_id}
    && scalar(keys %{$sessions}) >= $self->max_negentropy_sessions) {
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'NEG-ERR',
        subscription_id => $sub_id,
        message         => 'unavailable: too many negentropy sessions',
      )->serialize
    );
    return;
  }

  delete $sessions->{$sub_id};

  my $filter_hash = $msg->filter->to_hash;
  delete $filter_hash->{limit};
  my $unlimited_filter = Net::Nostr::Filter->new(%{$filter_hash});

  my $ne     = Net::Nostr::Negentropy->new;
  my $events = $self->store->query([$unlimited_filter]);
  for my $ev (@{$events}) {
    $ne->add_item($ev->created_at, $ev->id);
  }
  $ne->seal;

  my ($response, $have, $need);
  my $reconciled = eval {
    ($response, $have, $need) = $ne->reconcile($msg->neg_msg);
    1;
  };
  if (!$reconciled) {
    (my $reason = $EVAL_ERROR) =~ s/\n\z//mxs;
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'NEG-ERR',
        subscription_id => $sub_id,
        message         => "invalid: $reason",
      )->serialize
    );
    return;
  }

  if (defined $response) {
    $sessions->{$sub_id} = $ne;
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'NEG-MSG',
        subscription_id => $sub_id,
        neg_msg         => $response,
      )->serialize
    );
    return;
  }

  $conn->send(
    Net::Nostr::Message->new(
      type            => 'NEG-MSG',
      subscription_id => $sub_id,
      neg_msg         => '61',
    )->serialize
  );
  return;
}

sub _validate_overnet_publish {
  my ($self, $event) = @_;

  my $context = $self->_overnet_validation_context($event);
  my $result  = Overnet::Core::Validator::validate($event->to_hash, $context);
  if (!$result->{valid}) {
    return 'invalid: ' . $result->{reason};
  }

  my @mirror_errors = $self->_mirror_tag_errors($event);
  if (@mirror_errors) {
    return 'invalid: ' . $mirror_errors[0];
  }

  my $profile_error = $self->_profile_contract_index->validate_event($event);
  if ($profile_error) {
    return 'invalid: ' . $profile_error;
  }

  return;
}

sub _overnet_validation_context {
  my ($self, $event) = @_;
  my %tag_values = _first_tag_values($event->tags);
  my $context    = {};

  if ($event->kind == 7_801 && defined $tag_values{e}) {
    my $target_event = $self->store->get_by_id($tag_values{e});
    if ($target_event) {
      $context->{target_event} = $target_event->to_hash;
    }

    if (defined $tag_values{overnet_delegate}) {
      my $delegation_event = $self->store->get_by_id($tag_values{overnet_delegate});
      if ($delegation_event) {
        $context->{delegation_event} = $delegation_event->to_hash;
      }
    }
  }

  return $context;
}

sub _mirror_tag_errors {
  my ($self, $event) = @_;
  my %counts;
  my %values;

  for my $tag (@{$event->tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    $counts{$tag->[0]}++;
    if (!exists $values{$tag->[0]}) {
      $values{$tag->[0]} = $tag->[1];
    }
  }

  my @errors;
  my %mirror_for = (
    v => 'overnet_v',
    t => 'overnet_et',
    o => 'overnet_ot',
    d => 'overnet_oid',
  );

  for my $mirror (qw(v t o d)) {
    if (($counts{$mirror} // 0) > 1) {
      push @errors, "Duplicate $mirror tag";
    }
    if (!defined $values{$mirror}) {
      push @errors, "Missing required $mirror tag";
    }

    my $canonical = $mirror_for{$mirror};
    if ( defined $values{$mirror}
      && defined $values{$canonical}
      && $values{$mirror} ne $values{$canonical}) {
      push @errors, "$mirror tag must match $canonical";
    }
  }

  return @errors;
}

sub _normalized_supported_nips {
  my ($supported_nips) = @_;
  my %seen = map { $_ => 1 } @DEFAULT_SUPPORTED_NIPS;
  if (ref($supported_nips) eq 'ARRAY') {
    for my $supported_nip (@{$supported_nips}) {
      $seen{$supported_nip} = 1;
    }
  }
  return [sort { $a <=> $b } keys %seen];
}

sub _validated_service_policies {
  my ($service_policies) = @_;
  my %defaults = (
    publish     => 'open',
    query       => 'open',
    subscribe   => 'open',
    sync        => 'open',
    object_read => 'open',
  );

  if (defined $service_policies) {
    if (ref($service_policies) ne 'HASH') {
      croak 'service_policies must be an object';
    }
    %defaults = (%defaults, %{$service_policies});
  }

  for my $field (sort keys %defaults) {
    if (!$VALID_POLICY{$defaults{$field}}) {
      croak "Invalid service_policies value for $field";
    }
  }

  return \%defaults;
}

sub _decode_query_string {
  my ($query_string) = @_;
  my %query;
  if (!length $query_string) {
    return %query;
  }

  for my $pair (split /&/mxs, $query_string) {
    if (!length $pair) {
      next;
    }
    my ($key, $value) = split /=/mxs, $pair, 2;
    if (!defined $key) {
      next;
    }
    $query{uri_unescape($key)} = defined $value ? uri_unescape($value) : q{};
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
    )
    . "\r\n\r\n"
    . $body;
}

sub _write_all {
  my ($fh, $buffer) = @_;
  my $offset = 0;

  while ($offset < length($buffer)) {
    my $written = syswrite($fh, $buffer, length($buffer) - $offset, $offset);
    if (!defined $written) {
      if ($OS_ERROR{EINTR}) {
        next;
      }
      croak "Failed to write relay response: $OS_ERROR\n";
    }
    if ($written == 0) {
      croak "Failed to write relay response: wrote zero bytes\n";
    }
    $offset += $written;
  }

  return $offset;
}

sub _normalize_outcome_message {
  my ($message, $default_prefix, $default_detail) = @_;
  $default_detail //= q{};

  if (defined $message && !ref($message) && $message =~ /\A([a-z_]+):\s/smx) {
    if ($VALID_OUTCOME_PREFIX{$1}) {
      return $message;
    }
  }

  my $detail =
    defined $message && !ref($message) && length($message)
    ? $message
    : $default_detail;

  return $default_prefix . ': ' . $detail;
}

sub _object_is_removed {
  my ($state_event, $removal_event) = @_;
  if (!$removal_event) {
    return 0;
  }
  if (!$state_event) {
    return 1;
  }
  return _is_newer_event($removal_event, $state_event) ? 1 : 0;
}

sub _is_newer_event {
  my ($new, $existing) = @_;
  if ($new->created_at > $existing->created_at) {
    return 1;
  }
  if ($new->created_at == $existing->created_at && $new->id lt $existing->id) {
    return 1;
  }
  return 0;
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

1;

=head1 NAME

Overnet::Relay - First Overnet relay wrapper on top of Net::Nostr::Relay

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $relay = Overnet::Relay->new(relay_url => 'ws://127.0.0.1:7777');

=head1 DESCRIPTION

Adds Overnet validation, metadata, object reads, profile contracts, and
relay-to-relay sync ingestion behavior to L<Net::Nostr::Relay>.

=head1 SUBROUTINES/METHODS

=head2 new

Creates an Overnet relay.

=head2 accept_synced_event

  my $result = $relay->accept_synced_event($event);

Validates and ingests an event that arrived through relay-to-relay sync.
This follows the same Overnet event validation and replaceable/addressable
storage semantics as a normal publish, but it skips client-specific publish
controls such as per-connection rate limiting and author-authenticated
protected-event checks.

Returns a hashref containing C<accepted>, C<stored>, C<event_id>, and
C<message>.

=head2 name

Relay info name accessor.

=head2 description

Relay info description accessor.

=head2 banner

Relay info banner accessor.

=head2 icon

Relay info icon accessor.

=head2 admin_pubkey

Relay administrator public key accessor.

=head2 relay_pubkey

Relay public key accessor.

=head2 contact

Relay contact accessor.

=head2 software

Relay software accessor.

=head2 version

Relay software version accessor.

=head2 terms_of_service

Relay terms of service accessor.

=head2 payments_url

Relay payments URL accessor.

=head2 supported_nips

Supported NIP list accessor.

=head2 retention_seconds

Retention limit accessor.

=head2 max_negentropy_sessions

Maximum negentropy session count accessor.

=head2 core_version

Overnet core version accessor.

=head2 relay_profile

Overnet relay profile accessor.

=head2 profile_contract_policy

Profile contract policy accessor.

=head2 profile_contracts

Configured profile contracts accessor.

=head2 service_policies

Service policy map accessor.

=head2 pricing_url

Pricing URL accessor.

=head1 DIAGNOSTICS

Invalid constructor arguments are reported with C<croak>. Publish failures are
returned as Nostr relay outcome messages.

=head1 CONFIGURATION AND ENVIRONMENT

Relay behavior is configured through constructor arguments.

=head1 DEPENDENCIES

Requires L<AnyEvent>, L<JSON>, L<Net::Nostr>, L<Overnet::Core::Validator>, and
relay helper modules.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
