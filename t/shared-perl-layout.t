use strictures 2;

use File::Find ();
use File::Spec;
use FindBin;
use Test2::V0;

my $root = File::Spec->catdir($FindBin::Bin, '..');
my @perl_files;

File::Find::find(
  {
    wanted => sub {
      my $name = $File::Find::name;
      return if -d $name;
      return unless $name =~ /(?:\.PL|\.pm|\.pl|\.t)\z/mx;
      push @perl_files, $name;
      return;
    },
    no_chdir => 1,
  },
  map { File::Spec->catdir($root, $_) } qw(bin lib t xt)
);

for my $path (sort @perl_files) {
  open my $fh, '<', $path
    or die "open $path: $!";
  local $/ = undef;
  my $source = <$fh>;
  close $fh
    or die "close $path: $!";

  unlike $source, qr/local\/lib\/perl5/mx, "$path does not hard-code local-lib include paths";
}

done_testing;
