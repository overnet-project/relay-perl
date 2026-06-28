#!/usr/bin/env perl
use strictures 2;

use File::Spec;
use FindBin;

my $relay_script = File::Spec->catfile($FindBin::Bin, 'overnet-relay.pl');
exec $^X, $relay_script, @ARGV
  or die "exec failed: $!";
