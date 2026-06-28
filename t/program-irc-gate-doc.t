use strictures 2;
use Test::More;
use File::Spec;
use FindBin;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');
my $agents = File::Spec->catfile($FindBin::Bin, '..', 'AGENTS.md');

my $readme_text = _slurp($readme);
my $agents_text = _slurp($agents);

for my $doc (
  [ 'README', $readme_text ],
  [ 'AGENTS', $agents_text ],
) {
  my ($label, $text) = @{$doc};
  like $text, qr/IRC\ verification\ path/imx,
    "$label documents the IRC verification path";
  like $text, qr/t\/spec-conformance-irc-server\.t/mx,
    "$label includes server conformance in the IRC verification path";
  like $text, qr/t\/program-irc-server\.t/mx,
    "$label includes the fast IRC server suite in the IRC verification path";
  like $text, qr/t\/program-irc-server-relay\.t/mx,
    "$label includes the relay IRC server suite in the IRC verification path";
  like $text, qr/t\/program-irc-server-relay-fault\.t/mx,
    "$label includes the relay fault and recovery suite in the IRC verification path";
  like $text, qr/t\/program-irc-server-relay-failover\.t/mx,
    "$label includes the two-relay failover suite in the IRC verification path";
  like $text, qr/t\/relay-live\.t/mx,
    "$label includes live relay persistence and fault coverage in the IRC verification path";
  like $text, qr/t\/relay-sync-live\.t/mx,
    "$label includes live relay sync coverage in the IRC verification path";
  like $text, qr/t\/deploy-restore-drill-live\.t/mx,
    "$label includes the restore drill in the IRC verification path";
}

done_testing;
