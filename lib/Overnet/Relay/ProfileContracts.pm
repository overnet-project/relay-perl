package Overnet::Relay::ProfileContracts;

use strictures 2;

use Carp qw(croak);
use JSON ();
use Storable qw(dclone);

use Overnet::Core::ProfileContract ();

my %VALID_POLICY = map { $_ => 1 } qw(off known required);
my %CORE_EVENT_TYPE = map { $_ => 1 } qw(core.delegation core.removal);

sub new {
  my ($class, %args) = @_;

  my $input_contracts = $args{contracts};
  croak "profile_contracts must be an array reference"
    if defined $input_contracts && ref($input_contracts) ne 'ARRAY';

  my @contracts = map { dclone($_) } @{$input_contracts || []};
  my $policy = $args{policy};
  $policy = @contracts ? 'known' : 'off' unless defined $policy;
  croak "profile_contract_policy must be off, known, or required"
    unless !ref($policy) && $VALID_POLICY{$policy};
  $policy = 'off' unless @contracts;

  my $set = Overnet::Core::ProfileContract::validate_contract_set(\@contracts);
  croak "invalid profile_contracts: $set->{reason}"
    unless $set->{valid};

  my (%by_event_type, %profiles, %event_types);
  for my $contract (@contracts) {
    $profiles{$contract->{profile}} = 1 if defined $contract->{profile};
    for my $event_type_name (sort keys %{$contract->{event_types} || {}}) {
      push @{$by_event_type{$event_type_name}}, $contract;
      $event_types{$event_type_name} = 1;
    }
  }

  return bless {
    contracts => \@contracts,
    policy => $policy,
    by_event_type => \%by_event_type,
    profiles => [sort keys %profiles],
    event_types => [sort keys %event_types],
  }, $class;
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
  return unless @{$self->{contracts}};

  return {
    configured => JSON::true,
    enforced => $self->{policy} eq 'off' ? JSON::false : JSON::true,
    policy => $self->{policy},
    profiles => [@{$self->{profiles}}],
    event_types => [@{$self->{event_types}}],
  };
}

sub validate_event {
  my ($self, $event) = @_;
  return if $self->{policy} eq 'off';
  return unless @{$self->{contracts}};

  my $event_type_name = _event_type_name($event);
  my $matches = defined $event_type_name
    ? ($self->{by_event_type}{$event_type_name} || [])
    : [];

  if (!@{$matches}) {
    return if $self->{policy} eq 'known';
    return if defined $event_type_name && $CORE_EVENT_TYPE{$event_type_name};
    return 'profile_event.event_type_undefined';
  }

  my $result = @{$matches} == 1
    ? Overnet::Core::ProfileContract::validate_profile_event(
      event => $event,
      contract => $matches->[0],
    )
    : Overnet::Core::ProfileContract::validate_profile_event(
      event => $event,
      contracts => $self->{contracts},
    );

  return $result->{valid} ? undef : ($result->{reason} // $result->{errors}[0]);
}

sub _event_type_name {
  my ($event) = @_;
  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag};
    return $tag->[1] if $tag->[0] eq 'overnet_et' && @{$tag} >= 2;
  }
  return;
}

1;
