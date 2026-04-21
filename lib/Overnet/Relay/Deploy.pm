package Overnet::Relay::Deploy;

use strict;
use warnings;

use parent 'Overnet::Relay';

use Net::Nostr::Message;

sub _handle_event {
  my ($self, $conn_id, $event) = @_;
  my $conn = $self->_connections->{$conn_id};
  if (my $policy_error = $self->_service_policy_message('publish', $conn_id)) {
    $conn->send(Net::Nostr::Message->new(
      type => 'OK',
      event_id => ($event->id // ''),
      accepted => 0,
      message => $policy_error,
    )->serialize);
    return;
  }
  return $self->SUPER::_handle_event($conn_id, $event);
}

sub _handle_req {
  my ($self, $conn_id, $sub_id, @filters) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (my $policy_error = $self->_service_policy_message('query', $conn_id)
      || $self->_service_policy_message('subscribe', $conn_id)) {
    $conn->send(Net::Nostr::Message->new(
      type => 'CLOSED',
      subscription_id => $sub_id,
      message => $policy_error,
    )->serialize);
    return;
  }

  return $self->SUPER::_handle_req($conn_id, $sub_id, @filters);
}

sub _handle_neg_open {
  my ($self, $conn_id, $msg) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (my $policy_error = $self->_service_policy_message('sync', $conn_id)) {
    $conn->send(Net::Nostr::Message->new(
      type => 'NEG-ERR',
      subscription_id => $msg->subscription_id,
      code => 'blocked',
      reason => $policy_error,
    )->serialize);
    return;
  }

  return $self->SUPER::_handle_neg_open($conn_id, $msg);
}

sub _handle_object_http_request {
  my ($self, $method, $path) = @_;

  if (my $policy_error = $self->_service_policy_http_error('object_read')) {
    return $policy_error;
  }

  return $self->SUPER::_handle_object_http_request($method, $path);
}

sub _service_policy_message {
  my ($self, $service, $conn_id) = @_;
  my $policies = $self->service_policies || {};
  my $policy = $policies->{$service} || 'open';
  return undef if $policy eq 'open';

  if ($policy eq 'auth') {
    return undef if $self->_connection_is_authenticated($conn_id);
    return 'unauthorized: service requires authentication';
  }

  if ($policy eq 'paid') {
    return 'payment_required: service requires payment';
  }

  return 'policy_denied: service is closed';
}

sub _service_policy_http_error {
  my ($self, $service) = @_;
  my $message = $self->_service_policy_message($service, undef);
  return undef unless defined $message;

  my $status_line = 'HTTP/1.1 403 Forbidden';
  $status_line = 'HTTP/1.1 401 Unauthorized'
    if $message =~ /\Aunauthorized:/;
  $status_line = 'HTTP/1.1 402 Payment Required'
    if $message =~ /\Apayment_required:/;

  return join("\r\n",
    $status_line,
    'Content-Type: application/json',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Allow-Headers: Accept',
    'Access-Control-Allow-Methods: GET, OPTIONS',
    'Content-Length: ' . length($self->_service_policy_http_body($message)),
  ) . "\r\n\r\n" . $self->_service_policy_http_body($message);
}

sub _service_policy_http_body {
  my ($self, $message) = @_;
  require JSON::PP;
  return JSON::PP->new->utf8->canonical->encode({
    error => {
      code => ($message =~ /\A([a-z_]+):/ ? $1 : 'policy_denied'),
      message => $message,
    },
  });
}

sub _connection_is_authenticated {
  my ($self, $conn_id) = @_;
  return 0 unless defined $conn_id;
  my $authed = $self->_authenticated->{$conn_id};
  return 0 unless ref($authed) eq 'HASH';
  return scalar(keys %{$authed}) ? 1 : 0;
}

1;
