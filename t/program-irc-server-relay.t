use strict;
use warnings;

use File::Spec;
use FindBin;

BEGIN {
  $ENV{OVERNET_IRC_SERVER_GROUP} = 'relay';
}

my $path = File::Spec->catfile($FindBin::Bin, 'program-irc-server.t');
my $ok = do $path;

die $@ if !$ok && $@;
die "Unable to load $path: $!" unless defined $ok;

