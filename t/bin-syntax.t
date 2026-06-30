use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

my @scripts = (
  'bin/overnet-relay-backup.pl', 'bin/overnet-relay-service.pl',
  'bin/overnet-relay-sync.pl',   'bin/overnet-relay.pl',
  'bin/overnet-release-gate.pl',
);

plan tests => scalar @scripts;

for my $script (@scripts) {
  my $path = File::Spec->catfile($FindBin::Bin, '..', split m{/}mx, $script);
  my $ok   = system($^X, '-c', $path) == 0;
  ok $ok, "$script compiles";
}
