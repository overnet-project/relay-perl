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

# Persistence is an append-structured log so that storing N events costs O(N)
# total instead of O(N^2): each accepted event or deletion appends one record
# rather than rewriting the whole store. The log is periodically compacted back
# to one record per live event so the file stays bounded under churn.
my $COMPACT_MIN_RECORDS = 128;
my $COMPACT_LIVE_FACTOR = 2;

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
  $self->{_records_on_disk} = 0;
  $self->{_needs_rewrite}   = 0;
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
    $self->_persist_record([q{+}, $event->to_hash]);
  }
  return $stored;
}

sub delete_by_id {
  my ($self, $id) = @_;
  my $deleted = Net::Nostr::RelayStore::delete_by_id($self, $id);
  if ($deleted) {
    $self->_persist_record([q{-}, $id]);
  }
  return $deleted;
}

sub clear {
  my ($self) = @_;
  Net::Nostr::RelayStore::clear($self);
  $self->_compact_to_disk;
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
  my $raw = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh
    or croak "Can't close relay store file $path after reading: $OS_ERROR";

  if (!(defined $raw && length $raw)) {
    return 1;
  }

  my @lines   = split /\n/mxs, $raw;
  my $records = 0;
  for my $index (0 .. $#lines) {
    my $line = $lines[$index];
    if (!length $line) {
      next;
    }

    my $decoded;
    my $ok = eval {
      $decoded = $JSON->decode($line);
      1;
    };
    if (!$ok) {

      # A torn final line can result from a crash mid-append; tolerate it but
      # treat any earlier undecodable line as genuine corruption.
      if ($index == $#lines) {
        next;
      }
      croak "Invalid relay store file $path: $EVAL_ERROR";
    }

    $records += $self->_replay_record($path, $decoded);
  }

  $self->{_records_on_disk} = $records;

  # The on-disk log may hold the legacy single-array format, superseded
  # records, or tombstones. Leave the file untouched for read-only consumers
  # (for example the backup tool) and normalize it on the first mutation.
  $self->{_needs_rewrite} = $records ? 1 : 0;
  return 1;
}

sub _replay_record {
  my ($self, $path, $decoded) = @_;
  if (ref($decoded) ne 'ARRAY') {
    croak "Relay store file $path must contain array records";
  }

  my $tag = $decoded->[0];
  if (!@{$decoded} || ref($tag) eq 'HASH') {

    # Legacy format: one line holding the full array of wire events.
    my $count = 0;
    for my $wire (@{$decoded}) {
      if (ref($wire) ne 'HASH') {
        next;
      }
      Net::Nostr::RelayStore::store($self, Net::Nostr::Event->from_wire($wire));
      $count++;
    }
    return $count;
  }
  if (!ref($tag) && $tag eq q{+} && ref($decoded->[1]) eq 'HASH') {
    Net::Nostr::RelayStore::store($self, Net::Nostr::Event->from_wire($decoded->[1]));
    return 1;
  }
  if (!ref($tag) && $tag eq q{-} && defined $decoded->[1] && !ref($decoded->[1])) {
    Net::Nostr::RelayStore::delete_by_id($self, $decoded->[1]);
    return 1;
  }

  croak "Relay store file $path contains an unrecognized record";
}

sub _persist_record {
  my ($self, $entry) = @_;

  # A store loaded from a legacy or churned log is normalized on first write:
  # a single full rewrite replaces the whole file with one record per live
  # event, after which further writes append.
  if ($self->{_needs_rewrite}) {
    return $self->_compact_to_disk;
  }

  $self->_append_record($entry);
  $self->{_records_on_disk}++;

  my $live = $self->event_count;
  if ( $self->{_records_on_disk} >= $COMPACT_MIN_RECORDS
    && $self->{_records_on_disk} >= $COMPACT_LIVE_FACTOR * ($live + 1)) {
    $self->_compact_to_disk;
  }
  return 1;
}

sub _append_record {
  my ($self, $entry) = @_;
  my $path = $self->{path};
  $self->_ensure_directory($path);

  open my $fh, '>>:raw', $path
    or croak "Can't open relay store file $path for appending: $OS_ERROR";
  print {$fh} $JSON->encode($entry) . "\n"
    or croak "Can't append to relay store file $path: $OS_ERROR";
  close $fh
    or croak "Can't close relay store file $path after appending: $OS_ERROR";
  return 1;
}

sub _compact_to_disk {
  my ($self) = @_;
  my $path = $self->{path};
  $self->_ensure_directory($path);

  my @records = map { $JSON->encode([q{+}, $_->to_hash]) } @{$self->all_events || []};
  my $payload = @records ? join("\n", @records) . "\n" : q{};

  my $tmp_path = $path . '.tmp.' . $PROCESS_ID;
  open my $fh, '>:raw', $tmp_path
    or croak "Can't open relay store temp file $tmp_path for writing: $OS_ERROR";
  print {$fh} $payload
    or croak "Can't write relay store temp file $tmp_path: $OS_ERROR";
  close $fh
    or croak "Can't close relay store temp file $tmp_path: $OS_ERROR";

  rename $tmp_path, $path
    or croak "Can't rename relay store temp file $tmp_path to $path: $OS_ERROR";

  $self->{_records_on_disk} = scalar @records;
  $self->{_needs_rewrite}   = 0;
  return 1;
}

sub _ensure_directory {
  my ($self, $path) = @_;
  my $dir = dirname($path);
  if (!-d $dir) {
    make_path($dir);
  }
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

Persists relay events to disk while preserving the L<Net::Nostr::RelayStore>
API. Persistence is append-structured: each accepted event or deletion appends
one JSON-lines record rather than rewriting the whole store, so ingesting N
events costs O(N) total instead of O(N^2). The log is compacted back to one
record per live event once it outgrows the live set, keeping the file bounded
under churn. The legacy single-JSON-array format is still read, and is
normalized to the record log on the first subsequent write.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a file-backed store.

=head2 path

Returns the configured store path.

=head2 store

Stores an event and appends a persistence record if the event was accepted.

=head2 delete_by_id

Deletes an event and appends a tombstone record if an event was removed.

=head2 clear

Clears the store and rewrites the persisted state as empty.

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
