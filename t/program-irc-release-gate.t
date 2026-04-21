use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/;
  return <$fh>;
}

my $root = File::Spec->catdir($FindBin::Bin, '..');
my $script = File::Spec->catfile($root, 'bin', 'overnet-release-gate.pl');
my $readme = File::Spec->catfile($root, 'README.md');
my $claude = File::Spec->catfile($root, 'CLAUDE.md');

ok(-f $script, 'default IRC release gate script exists');

my $script_text = _slurp($script);
like $script_text, qr/t\/spec-conformance-irc-server\.t/,
  'release gate script runs server conformance';
like $script_text, qr/t\/program-irc-server\.t/,
  'release gate script runs the fast IRC server suite';
like $script_text, qr/t\/program-irc-server-relay\.t/,
  'release gate script runs the relay IRC server suite';
like $script_text, qr/t\/program-irc-server-relay-fault\.t/,
  'release gate script runs the relay fault and recovery suite';
like $script_text, qr/t\/program-irc-server-relay-failover\.t/,
  'release gate script runs the two-relay failover suite';
like $script_text, qr/t\/relay-live\.t/,
  'release gate script runs live relay persistence and fault tests';
like $script_text, qr/t\/relay-sync-live\.t/,
  'release gate script runs live relay sync tests';
like $script_text, qr/t\/deploy-restore-drill-live\.t/,
  'release gate script runs the restore drill live test';

for my $doc (
  [ 'README', _slurp($readme) ],
  [ 'CLAUDE', _slurp($claude) ],
) {
  my ($label, $text) = @{$doc};
  like $text, qr/default release gate/i,
    "$label identifies the default release gate";
  like $text, qr/bin\/overnet-release-gate\.pl/,
    "$label points to the release gate script";
}

done_testing;
