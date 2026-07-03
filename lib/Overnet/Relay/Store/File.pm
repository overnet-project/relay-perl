package Overnet::Relay::Store::File;

use strictures 2;
use Moo;

extends 'Net::Nostr::RelayStore';

use Carp           qw(croak);
use English        qw(-no_match_vars);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use JSON           ();
use Net::Nostr::Event;

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

has path => (is => 'rw');

around new => sub {
  my ($orig, $class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  my $path = delete $args{path};

  if (!(defined $path && !ref($path) && length($path))) {
    croak 'path is required';
  }

  my $self = $class->SUPER::new(\%args);
  $self->path($path);
  $self->_load_from_disk;
  return $self;
};

no Moo;

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub store {
  my ($self, $event) = @_;
  my $stored = Net::Nostr::RelayStore::store($self, $event);
  if ($stored) {
    $self->_persist_to_disk;
  }
  return $stored;
}

sub delete_by_id {
  my ($self, $id) = @_;
  my $deleted = Net::Nostr::RelayStore::delete_by_id($self, $id);
  if ($deleted) {
    $self->_persist_to_disk;
  }
  return $deleted;
}

sub clear {
  my ($self) = @_;
  Net::Nostr::RelayStore::clear($self);
  $self->_persist_to_disk;
  return 1;
}

sub _load_from_disk {
  my ($self) = @_;
  my $path = $self->{path};
  if (!-e $path) {
    return 1;
  }

  open my $fh, '<:raw', $path
    or croak "Can't open relay store file $path for reading: $OS_ERROR";
  local $INPUT_RECORD_SEPARATOR = undef;
  my $raw = <$fh>;
  close $fh
    or croak "Can't close relay store file $path after reading: $OS_ERROR";

  if (!(defined $raw && length $raw)) {
    return 1;
  }

  my $decoded;
  my $loaded = eval {
    $decoded = $JSON->decode($raw);
    1;
  };
  if (!$loaded) {
    croak "Invalid relay store file $path: $EVAL_ERROR";
  }
  if (ref($decoded) ne 'ARRAY') {
    croak "Relay store file $path must contain an array";
  }

  for my $wire (@{$decoded}) {
    if (ref($wire) ne 'HASH') {
      next;
    }
    my $event = Net::Nostr::Event->from_wire($wire);
    Net::Nostr::RelayStore::store($self, $event);
  }

  return 1;
}

sub _persist_to_disk {
  my ($self) = @_;
  my $path   = $self->{path};
  my $dir    = dirname($path);

  if (!-d $dir) {
    make_path($dir);
  }

  my $tmp_path = $path . '.tmp.' . $PROCESS_ID;
  open my $fh, '>:raw', $tmp_path
    or croak "Can't open relay store temp file $tmp_path for writing: $OS_ERROR";
  print {$fh} $JSON->encode([map { $_->to_hash } @{$self->all_events || []}])
    or croak "Can't write relay store temp file $tmp_path: $OS_ERROR";
  close $fh
    or croak "Can't close relay store temp file $tmp_path: $OS_ERROR";

  rename $tmp_path, $path
    or croak "Can't rename relay store temp file $tmp_path to $path: $OS_ERROR";

  return 1;
}

1;

=head1 NAME

Overnet::Relay::Store::File - File-backed Nostr relay store

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $store = Overnet::Relay::Store::File->new(path => 'relay-store.json');

=head1 DESCRIPTION

Persists relay events to a canonical JSON file while preserving the
L<Net::Nostr::RelayStore> API.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a file-backed store.

=head2 path

Returns the configured store path.

=head2 store

Stores an event and persists the store if the event was accepted.

=head2 delete_by_id

Deletes an event and persists the store if an event was removed.

=head2 clear

Clears the store and persists the empty state.

=head1 DIAGNOSTICS

Invalid store files and file-system errors are reported with C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

The caller supplies the JSON store path.

=head1 DEPENDENCIES

Requires L<JSON> and L<Net::Nostr::RelayStore>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
