use strictures 2;
use Test2::V0;
use File::Spec;
use FindBin;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $root   = File::Spec->catdir($FindBin::Bin, '..');
my $script = File::Spec->catfile($root, 'bin', 'overnet-release-gate.pl');
my $readme = File::Spec->catfile($root, 'README.md');
my $agents = File::Spec->catfile($root, 'AGENTS.md');

ok(-f $script, 'default IRC release gate script exists');

my $script_text = _slurp($script);
like $script_text, qr/t\/spec-conformance-irc-server\.t/mx, 'release gate script runs server conformance';
like $script_text, qr/t\/program-irc-server\.t/mx,          'release gate script runs the fast IRC server suite';
like $script_text, qr/t\/program-irc-server-relay\.t/mx,    'release gate script runs the relay IRC server suite';
like $script_text, qr/t\/program-irc-server-relay-fault\.t/mx,
  'release gate script runs the relay fault and recovery suite';
like $script_text, qr/t\/program-irc-server-relay-failover\.t/mx,
  'release gate script runs the two-relay failover suite';
like $script_text,   qr/t\/relay-live\.t/mx,      'release gate script runs live relay persistence and fault tests';
like $script_text,   qr/t\/relay-sync-live\.t/mx, 'release gate script runs live relay sync tests';
like $script_text,   qr/t\/deploy-restore-drill-live\.t/mx, 'release gate script runs the restore drill live test';
unlike $script_text, qr/\bplx\b/mx,                         'release gate does not assume plx is directly invokable';
unlike $script_text, qr/local\/lib\/perl5/mx,               'release gate does not add stale local-lib include paths';
like $script_text,   qr/\$EXECUTABLE_NAME/mx,               'release gate reuses the current project Perl executable';
like $script_text,   qr/'-S',\s*'prove'/mx,                 'release gate finds prove through the current Perl';

for my $doc (['README', _slurp($readme)], ['AGENTS', _slurp($agents)],) {
  my ($label, $text) = @{$doc};
  like $text, qr/default\ release\ gate/imx,       "$label identifies the default release gate";
  like $text, qr/bin\/overnet-release-gate\.pl/mx, "$label points to the release gate script";
}

done_testing;
