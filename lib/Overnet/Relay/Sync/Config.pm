package Overnet::Relay::Sync::Config;

use strictures 2;

use Carp    qw(croak);
use English qw(-no_match_vars);
use JSON    ();

use Net::Nostr::Filter;

our $VERSION = '0.001';

my $JSON         = JSON->new->utf8->canonical;
my %CONFIG_FIELD = map { $_ => 1 } qw(local_url timeout_seconds peers);
my %PEER_FIELD   = map { $_ => 1 } qw(name remote_url subscription_id filter);

sub load_file {
  my ($class, $path) = @_;
  if (!(defined $path && !ref($path) && length $path)) {
    croak 'config path is required';
  }

  open my $fh, '<:raw', $path
    or croak "unable to open config file $path: $OS_ERROR";
  local $INPUT_RECORD_SEPARATOR = undef;
  my $raw = <$fh>;
  close $fh
    or croak "unable to close config file $path: $OS_ERROR";

  my $data;
  my $decoded = eval {
    $data = $JSON->decode($raw);
    1;
  };
  if (!$decoded) {
    croak "invalid sync config JSON in $path: $EVAL_ERROR";
  }

  return $class->normalize($data);
}

sub normalize {
  my ($class, $data) = @_;
  if (ref($data) ne 'HASH') {
    croak 'sync config must be a JSON object';
  }

  _reject_unknown_fields(
    message => 'unknown sync config field(s)',
    known   => \%CONFIG_FIELD,
    data    => $data,
  );

  return {
    local_url       => _required_non_empty_string($data->{local_url}, 'sync config local_url'),
    timeout_seconds => _timeout_seconds($data->{timeout_seconds}),
    peers           => _normalized_peers($data->{peers}),
  };
}

sub _reject_unknown_fields {
  my (%args) = @_;
  my @unknown = grep { !$args{known}{$_} } keys %{$args{data}};
  if (@unknown) {
    croak "$args{message}: " . join ', ', sort @unknown;
  }

  return 1;
}

sub _required_non_empty_string {
  my ($value, $label) = @_;
  if (!(defined $value && !ref($value) && length $value)) {
    croak "$label is required";
  }

  return $value;
}

sub _optional_non_empty_string {
  my ($value, $label) = @_;
  if (!defined $value) {
    return;
  }
  if (ref($value) || $value eq q{}) {
    croak "$label must be a non-empty string";
  }

  return $value;
}

sub _timeout_seconds {
  my ($timeout_seconds) = @_;
  if (!defined $timeout_seconds) {
    $timeout_seconds = 5;
  }
  if (ref($timeout_seconds) || $timeout_seconds !~ /\A\d+\z/mxs || $timeout_seconds <= 0) {
    croak 'sync config timeout_seconds must be a positive integer';
  }

  return $timeout_seconds;
}

sub _normalized_peers {
  my ($peers) = @_;
  if (!(ref($peers) eq 'ARRAY' && @{$peers})) {
    croak 'sync config peers must be a non-empty array';
  }

  my %seen_name;
  my @normalized_peers;
  for my $index (0 .. $#{$peers}) {
    push @normalized_peers, _normalized_peer($peers->[$index], $index, \%seen_name);
  }

  return \@normalized_peers;
}

sub _normalized_peer {
  my ($peer, $index, $seen_name) = @_;
  if (ref($peer) ne 'HASH') {
    croak "sync config peer[$index] must be an object";
  }

  _reject_unknown_fields(
    message => "unknown sync peer[$index] field(s)",
    known   => \%PEER_FIELD,
    data    => $peer,
  );

  my $name = _optional_non_empty_string($peer->{name}, "sync config peer[$index] name");
  if (defined $name && $seen_name->{$name}++) {
    croak "duplicate sync peer name: $name";
  }

  my $subscription_id =
    _optional_non_empty_string($peer->{subscription_id}, "sync config peer[$index] subscription_id");
  my $filter_hash = _filter_hash($peer->{filter}, $index);

  return {
    (defined $name ? (name => $name) : ()),
    remote_url => _required_non_empty_string($peer->{remote_url}, "sync config peer[$index] remote_url"),
    (defined $subscription_id ? (subscription_id => $subscription_id) : ()),
    filter      => _filter($filter_hash, $index),
    filter_hash => {%{$filter_hash}},
  };
}

sub _filter_hash {
  my ($filter_hash, $index) = @_;
  if (ref($filter_hash) ne 'HASH') {
    croak "sync config peer[$index] filter must be an object";
  }

  return $filter_hash;
}

sub _filter {
  my ($filter_hash, $index) = @_;
  my $filter;
  my $built = eval {
    $filter = Net::Nostr::Filter->new(%{$filter_hash});
    1;
  };
  if (!$built) {
    croak "invalid sync config peer[$index] filter: $EVAL_ERROR";
  }

  return $filter;
}

1;

=head1 NAME

Overnet::Relay::Sync::Config - Static config loader for relay sync peers

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Relay::Sync::Config;

  my $config = Overnet::Relay::Sync::Config->load_file('sync.json');

=head1 DESCRIPTION

Loads and validates a static JSON config for relay sync jobs.

The current config shape is:

  {
    "local_url": "ws://127.0.0.1:7448",
    "timeout_seconds": 5,
    "peers": [
      {
        "name": "relay-a",
        "remote_url": "ws://127.0.0.1:7447",
        "subscription_id": "relay-a-sync",
        "filter": {
          "kinds": [37800],
          "#t": ["chat.topic"],
          "#o": ["chat.channel"],
          "#d": ["irc:sync:#overnet"]
        }
      }
    ]
  }

=head1 SUBROUTINES/METHODS

=head2 load_file

  my $config = Overnet::Relay::Sync::Config->load_file($path);

Loads, decodes, and validates a sync config JSON file.

=head2 normalize

  my $config = Overnet::Relay::Sync::Config->normalize($hashref);

Validates an already-decoded config structure and returns a normalized
hashref. Peer filter objects are converted into L<Net::Nostr::Filter>
instances and also preserved as raw C<filter_hash> structures.

=head1 DIAGNOSTICS

Invalid config input is reported with C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

This module reads the JSON sync config file supplied by the caller.

=head1 DEPENDENCIES

Requires L<JSON> and L<Net::Nostr::Filter>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
