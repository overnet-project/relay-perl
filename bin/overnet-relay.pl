#!/usr/bin/env perl
use strict;
use warnings;

use AnyEvent;
use File::Basename qw(dirname);
use File::Path qw(make_path);
use FindBin;
use Getopt::Long qw(GetOptions);
use JSON::PP ();
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../local/lib/perl5";
use lib "$FindBin::Bin/../../core-perl/lib";
use lib "$FindBin::Bin/../../core-perl/local/lib/perl5";

use Overnet::Relay::Deploy;
use Overnet::Relay::Store::File;

my %opt = (
  host => '127.0.0.1',
  port => 7447,
  name => 'Overnet Relay',
  description => 'Generic Overnet relay',
  software => 'https://example.invalid/overnet-relay',
  version => '0.1.0',
  core_version => '0.1.0',
  relay_profile => 'volunteer-basic',
  max_negentropy_sessions => 8,
  max_filters => 8,
  max_limit => 100,
  max_subscriptions => 32,
  max_message_length => 65536,
  max_content_length => 32768,
  max_connections_per_ip => undef,
  event_rate_limit => undef,
  min_pow_difficulty => undef,
  idle_timeout => undef,
  shutdown_timeout => undef,
  store_file => undef,
);

my $help = 0;
my $host = $opt{host};
my $port = $opt{port};
my @service_policy_args;
my $health_file;
my $log_file;

GetOptions(
  'host=s' => \$host,
  'port=i' => \$port,
  'name=s' => \$opt{name},
  'description=s' => \$opt{description},
  'software=s' => \$opt{software},
  'version=s' => \$opt{version},
  'core-version=s' => \$opt{core_version},
  'relay-profile=s' => \$opt{relay_profile},
  'max-negentropy-sessions=i' => \$opt{max_negentropy_sessions},
  'max-filters=i' => \$opt{max_filters},
  'max-limit=i' => \$opt{max_limit},
  'max-subscriptions=i' => \$opt{max_subscriptions},
  'max-message-length=i' => \$opt{max_message_length},
  'max-content-length=i' => \$opt{max_content_length},
  'max-connections-per-ip=i' => \$opt{max_connections_per_ip},
  'event-rate-limit=s' => \$opt{event_rate_limit},
  'min-pow-difficulty=i' => \$opt{min_pow_difficulty},
  'idle-timeout=i' => \$opt{idle_timeout},
  'shutdown-timeout=i' => \$opt{shutdown_timeout},
  'service-policy=s' => \@service_policy_args,
  'store-file=s' => \$opt{store_file},
  'health-file=s' => \$health_file,
  'log-file=s' => \$log_file,
  'help' => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--host is required\n" if !defined($host) || $host eq '';
die "--port must be a non-negative integer\n"
  if !defined($port) || $port !~ /\A\d+\z/;

for my $int_opt (
  qw(
    max_negentropy_sessions
    max_filters
    max_limit
    max_subscriptions
    max_message_length
    max_content_length
  )
) {
  die "--$int_opt must be a positive integer\n"
    if !defined($opt{$int_opt}) || $opt{$int_opt} !~ /\A\d+\z/ || $opt{$int_opt} < 1;
}

delete $opt{host};
delete $opt{port};

if (defined $log_file) {
  die "--log-file must be a non-empty string\n"
    if ref($log_file) || $log_file eq '';
  my $log_dir = dirname($log_file);
  make_path($log_dir) unless -d $log_dir;
  open my $log_fh, '>>', $log_file
    or die "Can't open relay log file $log_file: $!";
  open STDOUT, '>&', $log_fh
    or die "Can't redirect STDOUT to relay log file $log_file: $!";
  open STDERR, '>&', $log_fh
    or die "Can't redirect STDERR to relay log file $log_file: $!";
  select((select(STDOUT), $| = 1)[0]);
  select((select(STDERR), $| = 1)[0]);
}

my %relay_args = %opt;
if (defined $relay_args{store_file}) {
  die "--store-file must be a non-empty string\n"
    if ref($relay_args{store_file}) || $relay_args{store_file} eq '';
  $relay_args{store} = Overnet::Relay::Store::File->new(
    path => delete $relay_args{store_file},
  );
} else {
  delete $relay_args{store_file};
}
if (@service_policy_args) {
  $relay_args{service_policies} = _parse_service_policies(@service_policy_args);
}

my $relay = Overnet::Relay::Deploy->new(%relay_args);

my $shutdown = sub {
  _write_health_file($health_file, {
    status => 'stopping',
    listen_host => $host,
    listen_port => 0 + $port,
    details => {
      listen_host => $host,
      listen_port => 0 + $port,
    },
  }) if defined $health_file;
  print STDERR "[relay.health] stopping\n";
  $relay->stop;
};

$SIG{INT} = $shutdown;
$SIG{TERM} = $shutdown;

my $ready_timer;
if (defined $health_file) {
  $ready_timer = AnyEvent->timer(
    after => 0,
    cb => sub {
      undef $ready_timer;
      _write_health_file($health_file, {
        status => 'ready',
        listen_host => $host,
        listen_port => 0 + $port,
        details => {
          listen_host => $host,
          listen_port => 0 + $port,
          relay_profile => $relay->relay_profile,
          service_policies => $relay->service_policies,
        },
      });
      print STDERR "[relay.health] ready $host:$port\n";
    },
  );
} else {
  print STDERR "[relay.health] ready $host:$port\n";
}

$relay->run($host, $port);
_write_health_file($health_file, {
  status => 'stopped',
  listen_host => $host,
  listen_port => 0 + $port,
  details => {
    listen_host => $host,
    listen_port => 0 + $port,
  },
}) if defined $health_file;
print STDERR "[relay.health] stopped\n";
exit 0;

sub _parse_service_policies {
  my (@entries) = @_;
  my %policies;

  for my $entry (@entries) {
    die "--service-policy must be NAME=VALUE\n"
      unless defined $entry && !ref($entry) && $entry =~ /\A([a-z_]+)=([a-z_]+)\z/;
    $policies{$1} = $2;
  }

  return \%policies;
}

sub _write_health_file {
  my ($path, $payload) = @_;
  return 1 unless defined $path;

  die "--health-file must be a non-empty string\n"
    if ref($path) || $path eq '';

  my $dir = dirname($path);
  make_path($dir) unless -d $dir;

  my $tmp_path = $path . '.tmp.' . $$;
  open my $fh, '>', $tmp_path
    or die "Can't open relay health temp file $tmp_path: $!";
  print {$fh} JSON::PP->new->utf8->canonical->encode($payload)
    or die "Can't write relay health temp file $tmp_path: $!";
  close $fh
    or die "Can't close relay health temp file $tmp_path: $!";
  rename $tmp_path, $path
    or die "Can't rename relay health temp file $tmp_path to $path: $!";
  return 1;
}

sub _usage {
  return <<'USAGE';
Usage: overnet-relay.pl [options]

  --host HOST
  --port PORT
  --name NAME
  --description TEXT
  --software URL
  --version VERSION
  --core-version VERSION
  --relay-profile NAME
  --max-negentropy-sessions N
  --max-filters N
  --max-limit N
  --max-subscriptions N
  --max-message-length N
  --max-content-length N
  --max-connections-per-ip N
  --event-rate-limit COUNT/SECONDS
  --min-pow-difficulty N
  --idle-timeout SECONDS
  --shutdown-timeout SECONDS
  --service-policy NAME=VALUE
  --store-file PATH
  --health-file PATH
  --log-file PATH
  --help
USAGE
}
