#!/usr/bin/env perl
use strict;
use warnings;

use File::Spec;
use FindBin;

my $relay_script = File::Spec->catfile($FindBin::Bin, 'overnet-relay.pl');
exec $^X, $relay_script, @ARGV
  or die "exec failed: $!";
