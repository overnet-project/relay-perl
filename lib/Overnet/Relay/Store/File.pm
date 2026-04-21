package Overnet::Relay::Store::File;

use strict;
use warnings;

use parent 'Net::Nostr::RelayStore';

use File::Basename qw(dirname);
use File::Path qw(make_path);
use JSON::PP ();
use Net::Nostr::Event;

my $JSON = JSON::PP->new->utf8->canonical;

sub new {
  my ($class, %args) = @_;
  my $path = delete $args{path};

  die "path is required\n"
    unless defined $path && !ref($path) && length($path);

  my $self = $class->SUPER::new(%args);
  $self->{path} = $path;
  $self->_load_from_disk;
  return $self;
}

sub path {
  my ($self) = @_;
  return $self->{path};
}

sub store {
  my ($self, $event) = @_;
  my $stored = Net::Nostr::RelayStore::store($self, $event);
  $self->_persist_to_disk if $stored;
  return $stored;
}

sub delete_by_id {
  my ($self, $id) = @_;
  my $deleted = Net::Nostr::RelayStore::delete_by_id($self, $id);
  $self->_persist_to_disk if $deleted;
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
  return 1 unless -e $path;

  open my $fh, '<', $path
    or die "Can't open relay store file $path for reading: $!";
  local $/;
  my $raw = <$fh>;
  close $fh;

  return 1 unless defined $raw && length $raw;

  my $decoded = eval { $JSON->decode($raw) };
  die "Invalid relay store file $path: $@" if $@;
  die "Relay store file $path must contain an array\n"
    unless ref($decoded) eq 'ARRAY';

  for my $wire (@{$decoded}) {
    next unless ref($wire) eq 'HASH';
    my $event = Net::Nostr::Event->from_wire($wire);
    Net::Nostr::RelayStore::store($self, $event);
  }

  return 1;
}

sub _persist_to_disk {
  my ($self) = @_;
  my $path = $self->{path};
  my $dir = dirname($path);

  make_path($dir) unless -d $dir;

  my $tmp_path = $path . '.tmp.' . $$;
  open my $fh, '>', $tmp_path
    or die "Can't open relay store temp file $tmp_path for writing: $!";
  print {$fh} $JSON->encode([
    map { $_->to_hash } @{$self->all_events || []}
  ]) or die "Can't write relay store temp file $tmp_path: $!";
  close $fh or die "Can't close relay store temp file $tmp_path: $!";

  rename $tmp_path, $path
    or die "Can't rename relay store temp file $tmp_path to $path: $!";

  return 1;
}

1;
