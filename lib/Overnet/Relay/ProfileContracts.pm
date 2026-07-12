package Overnet::Relay::ProfileContracts;

use strictures 2;
use Moo;

use Carp     qw(croak);
use JSON     ();
use Storable qw(dclone);

use Overnet::Core::ProfileContract ();

our $VERSION = '0.001';

my %VALID_POLICY    = map { $_ => 1 } qw(off known required);
my %CORE_EVENT_TYPE = map { $_ => 1 } qw(core.delegation core.removal);

has contracts     => (is => 'ro', reader => '_contracts');
has policy        => (is => 'ro', reader => '_policy');
has by_event_type => (is => 'ro', reader => '_by_event_type');
has profiles      => (is => 'ro', reader => '_profiles');
has event_types   => (is => 'ro', reader => '_event_types');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $input_contracts = $args{contracts};
  croak "profile_contracts must be an array reference"
    if defined $input_contracts && ref($input_contracts) ne 'ARRAY';

  my @contracts = map { dclone($_) } @{$input_contracts || []};
  my $policy    = $args{policy};
  if (!defined $policy) {
    $policy = @contracts ? 'known' : 'off';
  }
  if (ref($policy) || !$VALID_POLICY{$policy}) {
    croak 'profile_contract_policy must be off, known, or required';
  }
  if (!@contracts) {
    $policy = 'off';
  }

  my $contract_set_result = Overnet::Core::ProfileContract::validate_contract_set(\@contracts);
  if (!$contract_set_result->{valid}) {
    croak "invalid profile_contracts: $contract_set_result->{reason}";
  }

  my (%by_event_type, %profiles, %event_types);
  for my $contract (@contracts) {

    # uncoverable branch false reason: contract set validation requires every contract to carry a profile
    if (defined $contract->{profile}) {
      $profiles{$contract->{profile}} = 1;
    }

    # uncoverable branch true reason: contract set validation requires event_types to be a non-empty hash
    for my $event_type_name (sort keys %{$contract->{event_types} || {}}) {
      push @{$by_event_type{$event_type_name}}, $contract;
      $event_types{$event_type_name} = 1;
    }
  }

  return {
    contracts     => \@contracts,
    policy        => $policy,
    by_event_type => \%by_event_type,
    profiles      => [sort keys %profiles],
    event_types   => [sort keys %event_types],
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub policy {
  my ($self) = @_;
  return $self->{policy};
}

sub contracts {
  my ($self) = @_;
  return [map { dclone($_) } @{$self->{contracts}}];
}

sub metadata {
  my ($self) = @_;
  if (!@{$self->{contracts}}) {
    return;
  }

  return {
    configured  => JSON::true,
    enforced    => $self->{policy} eq 'off' ? JSON::false : JSON::true,
    policy      => $self->{policy},
    profiles    => [@{$self->{profiles}}],
    event_types => [@{$self->{event_types}}],
  };
}

sub validate_event {
  my ($self, $event) = @_;
  if ($self->{policy} eq 'off') {
    return;
  }

  # uncoverable branch true reason: BUILDARGS forces the policy to off when no contracts are configured
  if (!@{$self->{contracts}}) {
    return;    # uncoverable statement reason: unreachable while an empty contract set implies the off policy
  }

  my $event_type_name = _event_type_name($event);
  my $matches =
    defined $event_type_name
    ? ($self->{by_event_type}{$event_type_name} || [])
    : [];

  if (!@{$matches}) {
    if ($self->{policy} eq 'known') {
      return;
    }
    if (defined $event_type_name && $CORE_EVENT_TYPE{$event_type_name}) {
      return;
    }
    return 'profile_event.event_type_undefined';
  }

  my $result =
    @{$matches} == 1
    ? Overnet::Core::ProfileContract::validate_profile_event(
    event    => $event,
    contract => $matches->[0],
    )
    : Overnet::Core::ProfileContract::validate_profile_event(
    event     => $event,
    contracts => $self->{contracts},
    );

  return $result->{valid} ? undef : ($result->{reason} // $result->{errors}[0]);
}

sub _event_type_name {
  my ($event) = @_;

  # uncoverable branch true reason: Net::Nostr::Event tags always default to an array reference
  for my $tag (@{$event->tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag})) {
      next;
    }
    if ($tag->[0] eq 'overnet_et' && @{$tag} >= 2) {
      return $tag->[1];
    }
  }
  return;
}

1;

=head1 NAME

Overnet::Relay::ProfileContracts - Relay profile contract enforcement helper

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $contracts = Overnet::Relay::ProfileContracts->new(
    contracts => \@contracts,
    policy    => 'known',
  );

=head1 DESCRIPTION

Indexes configured Overnet profile contracts and validates incoming Overnet
profile events against the configured relay enforcement policy.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a profile contract helper.

=head2 policy

Returns the enforcement policy.

=head2 contracts

Returns cloned profile contracts.

=head2 metadata

Returns relay info metadata for configured contracts.

=head2 validate_event

Returns a rejection reason for invalid events, or no value when the event is
accepted by the configured policy.

=head1 DIAGNOSTICS

Invalid contract configuration is reported with C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

The relay supplies configured profile contracts and policy.

=head1 DEPENDENCIES

Requires L<JSON>, L<Storable>, and L<Overnet::Core::ProfileContract>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
