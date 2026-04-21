package Overnet::Relay::Sync::Config;

use strict;
use warnings;

use Carp qw(croak);
use JSON::PP ();

use Net::Nostr::Filter;

my $JSON = JSON::PP->new->utf8->canonical;

sub load_file {
  my ($class, $path) = @_;
  croak "config path is required"
    unless defined $path && !ref($path) && length $path;

  open my $fh, '<:raw', $path
    or croak "unable to open config file $path: $!";
  local $/;
  my $raw = <$fh>;
  close $fh;

  my $data = eval { $JSON->decode($raw) };
  croak "invalid sync config JSON in $path: $@"
    if $@;

  return $class->normalize($data);
}

sub normalize {
  my ($class, $data) = @_;
  croak "sync config must be a JSON object"
    unless ref($data) eq 'HASH';

  my %known = map { $_ => 1 } qw(local_url timeout_seconds peers);
  my @unknown = grep { !$known{$_} } keys %{$data};
  croak "unknown sync config field(s): " . join(', ', sort @unknown)
    if @unknown;

  my $local_url = $data->{local_url};
  croak "sync config local_url is required"
    unless defined $local_url && !ref($local_url) && length $local_url;

  my $timeout_seconds = $data->{timeout_seconds};
  $timeout_seconds = 5 unless defined $timeout_seconds;
  croak "sync config timeout_seconds must be a positive integer"
    unless !ref($timeout_seconds) && $timeout_seconds =~ /\A\d+\z/ && $timeout_seconds > 0;

  my $peers = $data->{peers};
  croak "sync config peers must be a non-empty array"
    unless ref($peers) eq 'ARRAY' && @{$peers};

  my %seen_name;
  my @normalized_peers;
  for my $index (0 .. $#{$peers}) {
    my $peer = $peers->[$index];
    croak "sync config peer[$index] must be an object"
      unless ref($peer) eq 'HASH';

    my %peer_known = map { $_ => 1 } qw(name remote_url subscription_id filter);
    my @peer_unknown = grep { !$peer_known{$_} } keys %{$peer};
    croak "unknown sync peer[$index] field(s): " . join(', ', sort @peer_unknown)
      if @peer_unknown;

    my $name = $peer->{name};
    if (defined $name) {
      croak "sync config peer[$index] name must be a non-empty string"
        if ref($name) || $name eq '';
      croak "duplicate sync peer name: $name"
        if $seen_name{$name}++;
    }

    my $remote_url = $peer->{remote_url};
    croak "sync config peer[$index] remote_url is required"
      unless defined $remote_url && !ref($remote_url) && length $remote_url;

    my $subscription_id = $peer->{subscription_id};
    if (defined $subscription_id) {
      croak "sync config peer[$index] subscription_id must be a non-empty string"
        if ref($subscription_id) || $subscription_id eq '';
    }

    my $filter_hash = $peer->{filter};
    croak "sync config peer[$index] filter must be an object"
      unless ref($filter_hash) eq 'HASH';

    my $filter = eval { Net::Nostr::Filter->new(%{$filter_hash}) };
    croak "invalid sync config peer[$index] filter: $@"
      if $@;

    push @normalized_peers, {
      (defined $name ? (name => $name) : ()),
      remote_url => $remote_url,
      (defined $subscription_id ? (subscription_id => $subscription_id) : ()),
      filter => $filter,
      filter_hash => { %{$filter_hash} },
    };
  }

  return {
    local_url => $local_url,
    timeout_seconds => $timeout_seconds,
    peers => \@normalized_peers,
  };
}

1;

=head1 NAME

Overnet::Relay::Sync::Config - Static config loader for relay sync peers

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

=head1 METHODS

=head2 load_file

  my $config = Overnet::Relay::Sync::Config->load_file($path);

Loads, decodes, and validates a sync config JSON file.

=head2 normalize

  my $config = Overnet::Relay::Sync::Config->normalize($hashref);

Validates an already-decoded config structure and returns a normalized
hashref. Peer filter objects are converted into L<Net::Nostr::Filter>
instances and also preserved as raw C<filter_hash> structures.

=cut
