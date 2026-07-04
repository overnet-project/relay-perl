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

my $root = File::Spec->catdir($FindBin::Bin, '..', '..');

my @readmes = (
  File::Spec->catfile($root, 'spec',             'README.md'),
  File::Spec->catfile($root, 'core-perl',        'README.md'),
  File::Spec->catfile($root, 'relay-perl',       'README.md'),
  File::Spec->catfile($root, 'adapter-irc-perl', 'README.md'),
  File::Spec->catfile($root, 'irc-server',       'README.md'),
  File::Spec->catfile($root, 'relay-perl',       'deploy', 'canary', 'README.md'),
  File::Spec->catfile($root, 'irc-server',       'deploy', 'canary', 'README.md'),
);

for my $path (@readmes) {
  my $text = _slurp($path);
  unlike $text, qr/\bplx\b/imx,                "$path does not mention plx";
  unlike $text, qr{(?:^|[`\s])local/}imx,      "$path does not mention local/ build paths";
  unlike $text, qr{/home/_73\b}mx,             "$path does not mention personal home-directory paths";
  unlike $text, qr{/opt/perl(?:-[\d.]+)?\b}mx, "$path does not mention machine-specific Perl install paths";
  unlike $text, qr{\.plx/}mx,                  "$path does not mention .plx build paths";
}

done_testing;
