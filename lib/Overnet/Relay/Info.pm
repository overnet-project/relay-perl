package Overnet::Relay::Info;

use strict;
use warnings;

use Carp qw(croak);
use JSON::PP ();

use Class::Tiny qw(
  name
  description
  banner
  icon
  pubkey
  self
  contact
  software
  version
  terms_of_service
  payments_url
  overnet
  _supported_nips
  _limitation
  _fees
);

my @SCALAR_FIELDS = qw(
  name description banner icon pubkey self contact
  software version terms_of_service payments_url
);

my @STRUCT_FIELDS = qw(supported_nips limitation fees overnet);
my $JSON = JSON::PP->new->utf8->canonical;

sub new {
  my ($class, %args) = @_;

  my %known = map { $_ => 1 } (@SCALAR_FIELDS, @STRUCT_FIELDS);
  my @unknown = grep { !$known{$_} } keys %args;
  croak "unknown argument(s): " . join(', ', sort @unknown)
    if @unknown;

  my $self = bless {}, $class;
  for my $field (@SCALAR_FIELDS) {
    $self->{$field} = $args{$field}
      if exists $args{$field};
  }

  $self->{_supported_nips} = [@{$args{supported_nips} || []}];
  $self->{_limitation} = ref($args{limitation}) eq 'HASH'
    ? { %{$args{limitation}} }
    : undef;
  $self->{_fees} = ref($args{fees}) eq 'HASH'
    ? { %{$args{fees}} }
    : undef;
  $self->overnet(
    ref($args{overnet}) eq 'HASH' ? { %{$args{overnet}} } : undef
  );

  return $self;
}

sub supported_nips {
  my ($self) = @_;
  return [@{$self->{_supported_nips} || []}];
}

sub limitation {
  my ($self) = @_;
  return defined $self->{_limitation} ? { %{$self->{_limitation}} } : undef;
}

sub fees {
  my ($self) = @_;
  return defined $self->{_fees} ? { %{$self->{_fees}} } : undef;
}

sub to_hash {
  my ($self) = @_;
  my %doc;

  for my $field (@SCALAR_FIELDS) {
    $doc{$field} = $self->$field if defined $self->$field;
  }

  my $supported_nips = $self->supported_nips;
  $doc{supported_nips} = $supported_nips if @{$supported_nips};

  my $limitation = $self->limitation;
  $doc{limitation} = $limitation if defined $limitation;

  my $fees = $self->fees;
  $doc{fees} = $fees if defined $fees;

  my $overnet = $self->overnet;
  $doc{overnet} = { %{$overnet} } if defined $overnet;

  return \%doc;
}

sub to_json {
  my ($self) = @_;
  return $JSON->encode($self->to_hash);
}

my @CORS_HEADERS = (
  'Access-Control-Allow-Origin: *',
  'Access-Control-Allow-Headers: Accept',
  'Access-Control-Allow-Methods: GET, OPTIONS',
);

sub to_http_response {
  my ($self) = @_;
  my $body = $self->to_json;
  return join("\r\n",
    'HTTP/1.1 200 OK',
    'Content-Type: application/nostr+json',
    @CORS_HEADERS,
    'Content-Length: ' . length($body),
  ) . "\r\n\r\n" . $body;
}

sub cors_preflight_response {
  return join("\r\n",
    'HTTP/1.1 204 No Content',
    @CORS_HEADERS,
    'Content-Length: 0',
    '',
    '',
  );
}

1;

=head1 NAME

Overnet::Relay::Info - NIP-11 relay info document with Overnet metadata

=cut
