use strict;
use warnings;

use FindBin;
use File::Spec;
use Test::More;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib');

use Overnet::Test::SpecConformance qw(
  run_irc_server_conformance
);

run_irc_server_conformance();

done_testing;
