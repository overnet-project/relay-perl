#!/usr/bin/env perl
use strict;
use warnings;

use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Path qw(make_path);
use FindBin;
use Getopt::Long qw(GetOptions);
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../local/lib/perl5";
use lib "$FindBin::Bin/../../core-perl/lib";
use lib "$FindBin::Bin/../../core-perl/local/lib/perl5";

use Overnet::Relay::Store::File;

my %opt;
my $help = 0;

GetOptions(
  'source-store-file=s' => \$opt{source_store_file},
  'backup-file=s'       => \$opt{backup_file},
  'help'                => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--source-store-file is required\n"
  unless defined $opt{source_store_file}
    && !ref($opt{source_store_file})
    && length($opt{source_store_file});
die "--backup-file is required\n"
  unless defined $opt{backup_file}
    && !ref($opt{backup_file})
    && length($opt{backup_file});
die "--source-store-file does not exist\n"
  unless -f $opt{source_store_file};

Overnet::Relay::Store::File->new(
  path => $opt{source_store_file},
);

my $backup_dir = dirname($opt{backup_file});
make_path($backup_dir)
  unless -d $backup_dir;

copy($opt{source_store_file}, $opt{backup_file})
  or die "Can't copy $opt{source_store_file} to $opt{backup_file}: $!";

Overnet::Relay::Store::File->new(
  path => $opt{backup_file},
);

print $opt{backup_file}, "\n";
exit 0;

sub _usage {
  return <<'USAGE';
Usage: overnet-relay-backup.pl [options]

  --source-store-file PATH
  --backup-file PATH
  --help
USAGE
}
