use strictures 2;

use Cwd qw(getcwd);
use File::Spec;
use FindBin;
use Test2::V0;

my $makefile_pl = File::Spec->catfile($FindBin::Bin, '..', 'Makefile.PL');

ok -f $makefile_pl, 'Makefile.PL exists'
  or bail_out('Makefile.PL is required');

my $args = _capture_makefile_args($makefile_pl);

is $args->{NAME},             'Overnet::Relay',                                                    'distribution name';
is $args->{DISTNAME},         'Overnet-Relay',                                                     'CPAN dist name';
is $args->{AUTHOR},           'Nicholas B. Hubbard <nicholashubbard@posteo.net>',                  'author';
is $args->{ABSTRACT},         'Perl reference implementation of the Overnet relay and relay sync', 'abstract';
is $args->{VERSION_FROM},     'lib/Overnet/Relay.pm', 'version comes from relay module';
is $args->{LICENSE},          'gpl_3',                'license';
is $args->{MIN_PERL_VERSION}, '5.040',                'minimum Perl version';
is(
  $args->{CONFIGURE_REQUIRES},
  {
    'ExtUtils::MakeMaker' => 0,
  },
  'configure prerequisites include modules required to load Makefile.PL',
);

is(
  $args->{PREREQ_PM},
  {
    'AnyEvent'       => 0,
    'JSON'           => 0,
    'Moo'            => 0,
    'Net::Nostr'     => 0,
    'Overnet'        => 0.001,
    'Package::Stash' => 0,
    'strictures'     => 2,
    'URI'            => 0,
  },
  'runtime prerequisites stay on top-level non-core distributions',
);

is(
  $args->{TEST_REQUIRES},
  {
    'AnyEvent::WebSocket::Client' => 0,
  },
  'test-only prerequisites are declared in Makefile.PL',
);

is(
  $args->{EXE_FILES},
  ['bin/overnet-relay-backup.pl', 'bin/overnet-relay-service.pl', 'bin/overnet-relay-sync.pl', 'bin/overnet-relay.pl',],
  'installable relay scripts are explicit',
);

is(
  $args->{META_MERGE},
  {
    resources => {
      repository => 'https://github.com/overnet-project/relay-perl',
      bugtracker => 'https://github.com/overnet-project/relay-perl/issues',
    },
  },
  'metadata resources point at the public repo',
);

is(
  $args->{test},
  {
    TESTS => join(
      ' ',
      qw(
        t/bin-syntax.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/relay-cli-profile-contracts.t
        t/relay-profile-contracts.t
        t/relay.t
        t/repo-split.t
      )
    ),
  },
  'default test suite excludes live and sibling-coupled integration coverage',
);

done_testing;

sub _capture_makefile_args {
  my ($makefile_pl) = @_;
  my $args;
  my $cwd = getcwd();
  my ($volume, $dirs) = File::Spec->splitpath($makefile_pl);
  my $repo_root = File::Spec->catpath($volume, $dirs, '');
  $repo_root =~ s{/$}{}mx;

  {
    require ExtUtils::MakeMaker;

    no warnings qw(redefine once);
    local *ExtUtils::MakeMaker::WriteMakefile = sub {
      $args = {@_};
      return 1;
    };
    local *main::WriteMakefile = \&ExtUtils::MakeMaker::WriteMakefile;

    chdir $repo_root or die "unable to chdir to $repo_root: $!";
    my $rv    = do $makefile_pl;
    my $error = $@;
    chdir $cwd or die "unable to restore cwd to $cwd: $!";

    die $error if $error;
    die "unable to load $makefile_pl: $!" unless defined $rv;
  }

  return $args;
}
