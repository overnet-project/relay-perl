use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my @scripts = (
  'bin/overnet-relay-backup.pl',
  'bin/overnet-relay-service.pl',
  'bin/overnet-relay-sync.pl',
  'bin/overnet-relay.pl',
);

plan tests => scalar @scripts;

for my $script (@scripts) {
  my $path = File::Spec->catfile($FindBin::Bin, '..', split m{/}, $script);
  my $ok = system($^X, '-c', $path) == 0;
  ok $ok, "$script compiles";
}
