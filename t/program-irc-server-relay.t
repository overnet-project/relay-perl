use strictures 2;

use File::Spec;
use FindBin;

BEGIN {
  $ENV{OVERNET_IRC_SERVER_GROUP} = 'relay';
}

my $path = File::Spec->catfile($FindBin::Bin, 'program-irc-server.t');
-f $path or die "Unable to find $path";

do $path;
die $@ if $@;

