use strict;
use warnings;

use FindBin;
use File::Spec;
use Test::More;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');

use Overnet::Test::SpecConformance qw(
  run_irc_server_conformance
);

run_irc_server_conformance();

done_testing;
