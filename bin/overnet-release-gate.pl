#!/usr/bin/env perl
use strictures 2;
use Carp           qw(croak);
use English        qw(-no_match_vars);
use File::Basename qw(dirname);
use File::Spec;

our $VERSION = '0.001';

my $root = File::Spec->catdir(dirname($PROGRAM_NAME), File::Spec->updir());
chdir $root
  or croak "Can't chdir to $root: $OS_ERROR\n";

exec $EXECUTABLE_NAME, '-S', 'prove',
  '-Ilib',
  '-I../core-perl/lib',
  't/spec-conformance-irc-server.t',
  't/program-irc-server.t',
  't/program-irc-server-relay.t',
  't/program-irc-server-relay-fault.t',
  't/program-irc-server-relay-failover.t', 't/relay-live.t', 't/relay-sync-live.t', 't/deploy-restore-drill-live.t'
  or croak "Can't exec prove: $OS_ERROR\n";
