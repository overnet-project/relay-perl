#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use Getopt::Long qw(GetOptions);
use JSON::PP ();
use lib grep { -d $_ } (
  "$FindBin::Bin/../lib",
  "$FindBin::Bin/../../core-perl/lib",
);

use Overnet::Relay::Sync;
use Overnet::Relay::Sync::Config;

my $JSON = JSON::PP->new->utf8->canonical;

my $config_path = '';
my $help = 0;

GetOptions(
  'config=s' => \$config_path,
  'help' => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--config is required\n"
  unless defined $config_path && $config_path ne '';

my $config = Overnet::Relay::Sync::Config->load_file($config_path);
my $sync = Overnet::Relay::Sync->new(
  local_url => $config->{local_url},
  timeout_seconds => $config->{timeout_seconds},
);

my @results;
for my $peer (@{$config->{peers}}) {
  my $result = $sync->sync_once(
    remote_url => $peer->{remote_url},
    local_url => $config->{local_url},
    filter => $peer->{filter},
    (defined $peer->{subscription_id}
      ? (subscription_id => $peer->{subscription_id})
      : ()),
  );

  push @results, {
    (defined $peer->{name} ? (name => $peer->{name}) : ()),
    remote_url => $peer->{remote_url},
    filter => $peer->{filter_hash},
    %{$result},
  };
}

print $JSON->encode({
  local_url => $config->{local_url},
  peer_count => scalar(@results),
  results => \@results,
}) . "\n";

exit 0;

sub _usage {
  return <<'USAGE';
Usage: overnet-relay-sync.pl --config sync.json

Static sync config shape:

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
USAGE
}
