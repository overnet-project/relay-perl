package Overnet::Relay::Info;

use strictures 2;
use Moo;

use Carp qw(croak);
use JSON ();

our $VERSION = '0.001';

my @SCALAR_FIELDS = qw(
  name description banner icon pubkey self contact
  software version terms_of_service payments_url
);

my @STRUCT_FIELDS = qw(supported_nips limitation fees overnet);
my $JSON          = JSON->new->utf8->canonical;

has name             => (is => 'ro');
has description      => (is => 'ro');
has banner           => (is => 'ro');
has icon             => (is => 'ro');
has pubkey           => (is => 'ro');
has self             => (is => 'ro');
has contact          => (is => 'ro');
has software         => (is => 'ro');
has version          => (is => 'ro');
has terms_of_service => (is => 'ro');
has payments_url     => (is => 'ro');
has overnet          => (is => 'ro');
has _supported_nips  => (is => 'ro');
has _limitation      => (is => 'ro');
has _fees            => (is => 'ro');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my %known   = map  { $_ => 1 } (@SCALAR_FIELDS, @STRUCT_FIELDS);
  my @unknown = grep { !$known{$_} } keys %args;
  if (@unknown) {
    croak 'unknown argument(s): ' . join ', ', sort @unknown;
  }

  my %state;
  for my $field (@SCALAR_FIELDS) {
    if (exists $args{$field}) {
      $state{$field} = $args{$field};
    }
  }

  $state{_supported_nips} = [@{$args{supported_nips} || []}];
  $state{_limitation} =
    ref($args{limitation}) eq 'HASH'
    ? {%{$args{limitation}}}
    : undef;
  $state{_fees} =
    ref($args{fees}) eq 'HASH'
    ? {%{$args{fees}}}
    : undef;
  $state{overnet} = ref($args{overnet}) eq 'HASH' ? {%{$args{overnet}}} : undef;

  return \%state;
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub supported_nips {
  my ($self) = @_;
  return [@{$self->{_supported_nips} || []}];
}

sub limitation {
  my ($self) = @_;
  return defined $self->{_limitation} ? {%{$self->{_limitation}}} : undef;
}

sub fees {
  my ($self) = @_;
  return defined $self->{_fees} ? {%{$self->{_fees}}} : undef;
}

sub to_hash {
  my ($self) = @_;
  my %doc;

  for my $field (@SCALAR_FIELDS) {
    if (defined $self->$field) {
      $doc{$field} = $self->$field;
    }
  }

  my $supported_nips = $self->supported_nips;
  if (@{$supported_nips}) {
    $doc{supported_nips} = $supported_nips;
  }

  my $limitation = $self->limitation;
  if (defined $limitation) {
    $doc{limitation} = $limitation;
  }

  my $fees = $self->fees;
  if (defined $fees) {
    $doc{fees} = $fees;
  }

  my $overnet = $self->overnet;
  if (defined $overnet) {
    $doc{overnet} = {%{$overnet}};
  }

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
    @CORS_HEADERS, 'Content-Length: ' . length($body),
    )
    . "\r\n\r\n"
    . $body;
}

sub cors_preflight_response {
  return join "\r\n", 'HTTP/1.1 204 No Content', @CORS_HEADERS, 'Content-Length: 0', q{}, q{};
}

1;

=head1 NAME

Overnet::Relay::Info - NIP-11 relay info document with Overnet metadata

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $info = Overnet::Relay::Info->new(name => 'relay');
  my $json = $info->to_json;

=head1 DESCRIPTION

Builds canonical NIP-11 relay information documents with Overnet-specific
metadata.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a relay info document.

=head2 name

Relay name accessor.

=head2 description

Relay description accessor.

=head2 banner

Relay banner accessor.

=head2 icon

Relay icon accessor.

=head2 pubkey

Relay administrator public key accessor.

=head2 self

Relay self public key accessor.

=head2 contact

Relay contact accessor.

=head2 software

Relay software accessor.

=head2 version

Relay software version accessor.

=head2 terms_of_service

Terms of service accessor.

=head2 payments_url

Payments URL accessor.

=head2 overnet

Overnet metadata accessor.

=head2 supported_nips

Returns the supported NIP numbers.

=head2 limitation

Returns relay limitation metadata.

=head2 fees

Returns relay fee metadata.

=head2 to_hash

Returns the NIP-11 document as a hashref.

=head2 to_json

Returns the NIP-11 document as canonical JSON.

=head2 to_http_response

Returns an HTTP response for the info document.

=head2 cors_preflight_response

Returns the CORS preflight HTTP response.

=head1 DIAGNOSTICS

Unknown constructor arguments are reported with C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

All relay info fields are supplied by the caller.

=head1 DEPENDENCIES

Requires L<Moo> and L<JSON>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
