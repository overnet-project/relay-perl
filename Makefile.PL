use strict;
use warnings;

use ExtUtils::MakeMaker;

our $VERSION = '0.001';

my $space = chr 32;

WriteMakefile(
  NAME               => 'Overnet::Relay',
  DISTNAME           => 'Overnet-Relay',
  AUTHOR             => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT           => 'Perl reference implementation of the Overnet relay and relay sync',
  VERSION_FROM       => 'lib/Overnet/Relay.pm',
  LICENSE            => 'gpl_3',
  MIN_PERL_VERSION   => '5.040',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 0,
  },
  PREREQ_PM => {
    'AnyEvent'       => 0,
    'JSON'           => 0,
    'Moo'            => 0,
    'Net::Nostr'     => 0,
    'Overnet'        => 0.001,
    'Package::Stash' => 0,
    'URI'            => 0,
    'strictures'     => 2,
  },
  TEST_REQUIRES => {
    'AnyEvent::WebSocket::Client' => 0,
  },
  EXE_FILES => [
    'bin/overnet-relay-backup.pl', 'bin/overnet-relay-service.pl',
    'bin/overnet-relay-sync.pl',   'bin/overnet-relay.pl',
  ],
  test => {
    TESTS => join(
      $space,
      qw(
        t/bin-syntax.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/relay-cli-profile-contracts.t
        t/relay-deploy.t
        t/relay-info.t
        t/relay-profile-contracts.t
        t/relay-store-file.t
        t/relay-sync-config.t
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
