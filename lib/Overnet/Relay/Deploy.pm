package Overnet::Relay::Deploy;

use strictures 2;

use parent 'Overnet::Relay';

use JSON ();
use Net::Nostr::Message;

our $VERSION = '0.001';

sub _handle_event {
  my ($self, $conn_id, $event) = @_;
  my $conn = $self->_connections->{$conn_id};
  if (my $policy_error = $self->_service_policy_message('publish', $conn_id)) {
    $conn->send(
      Net::Nostr::Message->new(
        type     => 'OK',
        event_id => ($event->id // q{}),
        accepted => 0,
        message  => $policy_error,
      )->serialize
    );
    return;
  }
  return $self->SUPER::_handle_event($conn_id, $event);
}

sub _handle_req {
  my ($self, $conn_id, $sub_id, @filters) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (my $policy_error = $self->_service_policy_message('query', $conn_id)
    || $self->_service_policy_message('subscribe', $conn_id)) {
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'CLOSED',
        subscription_id => $sub_id,
        message         => $policy_error,
      )->serialize
    );
    return;
  }

  return $self->SUPER::_handle_req($conn_id, $sub_id, @filters);
}

sub _handle_neg_open {
  my ($self, $conn_id, $msg) = @_;
  my $conn = $self->_connections->{$conn_id};

  if (my $policy_error = $self->_service_policy_message('sync', $conn_id)) {
    $conn->send(
      Net::Nostr::Message->new(
        type            => 'NEG-ERR',
        subscription_id => $msg->subscription_id,
        code            => 'blocked',
        reason          => $policy_error,
      )->serialize
    );
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
  my $policy   = $policies->{$service}   || 'open';
  if ($policy eq 'open') {
    return;
  }

  if ($policy eq 'auth') {
    if ($self->_connection_is_authenticated($conn_id)) {
      return;
    }
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
  if (!defined $message) {
    return;
  }

  my $status_line = 'HTTP/1.1 403 Forbidden';
  if ($message =~ /\Aunauthorized:/mxs) {
    $status_line = 'HTTP/1.1 401 Unauthorized';
  }
  if ($message =~ /\Apayment_required:/mxs) {
    $status_line = 'HTTP/1.1 402 Payment Required';
  }

  return join("\r\n",
    $status_line,
    'Content-Type: application/json',
    'Access-Control-Allow-Origin: *',
    'Access-Control-Allow-Headers: Accept',
    'Access-Control-Allow-Methods: GET, OPTIONS',
    'Content-Length: ' . length($self->_service_policy_http_body($message)),
    )
    . "\r\n\r\n"
    . $self->_service_policy_http_body($message);
}

sub _service_policy_http_body {
  my ($self, $message) = @_;
  return JSON->new->utf8->canonical->encode(
    {
      error => {
        code    => ($message =~ /\A([a-z_]+):/mxs ? $1 : 'policy_denied'),
        message => $message,
      },
    }
  );
}

sub _connection_is_authenticated {
  my ($self, $conn_id) = @_;
  if (!defined $conn_id) {
    return 0;
  }
  my $authed = $self->_authenticated->{$conn_id};
  if (ref($authed) ne 'HASH') {
    return 0;
  }
  return scalar(keys %{$authed}) ? 1 : 0;
}

1;

=head1 NAME

Overnet::Relay::Deploy - Deployment policy wrapper for the Overnet relay

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $relay = Overnet::Relay::Deploy->new(service_policies => \%policies);

=head1 DESCRIPTION

Extends L<Overnet::Relay> with deploy-time service policy enforcement for
publish, query, subscribe, sync, and object read paths.

=head1 SUBROUTINES/METHODS

This package uses the public constructor and API inherited from
L<Overnet::Relay>.

=head1 DIAGNOSTICS

Denied services return protocol-level policy errors.

=head1 CONFIGURATION AND ENVIRONMENT

Service policies are supplied by the relay configuration.

=head1 DEPENDENCIES

Requires L<Overnet::Relay>, L<JSON>, and L<Net::Nostr::Message>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
