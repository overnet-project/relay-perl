use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME             => 'Overnet::Relay',
  DISTNAME         => 'Overnet-Relay',
  AUTHOR           => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT         => 'Perl reference implementation of the Overnet relay and relay sync',
  VERSION_FROM     => 'lib/Overnet/Relay.pm',
  LICENSE          => 'gpl_3',
  MIN_PERL_VERSION => '5.024',
  PREREQ_PM        => {
    'AnyEvent'    => 0,
    'Class::Tiny' => 0,
    'Net::Nostr'  => 0,
    'Overnet'     => 0.001,
    'URI'         => 0,
  },
  EXE_FILES        => [
    'bin/overnet-relay-backup.pl',
    'bin/overnet-relay-service.pl',
    'bin/overnet-relay-sync.pl',
    'bin/overnet-relay.pl',
  ],
  test => {
    TESTS => join(
      ' ',
      qw(
        t/bin-syntax.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/relay.t
        t/repo-split.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/relay-perl',
      bugtracker => 'https://github.com/overnet-project/relay-perl/issues',
    },
  },
);
