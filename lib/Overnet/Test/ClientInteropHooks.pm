package Overnet::Test::ClientInteropHooks;

use strictures 2;

use Package::Stash ();

our $VERSION = '0.001';

BEGIN {
  my $fixed_challenge = $ENV{OVERNET_FIXED_AUTH_CHALLENGE};
  if (defined($fixed_challenge) && !ref($fixed_challenge) && length($fixed_challenge)) {
    require Overnet::Program::IRC::Server;

    my $stash = Package::Stash->new('Overnet::Program::IRC::Server');
    $stash->remove_symbol('&_generate_authoritative_auth_challenge');
    $stash->add_symbol(
      '&_generate_authoritative_auth_challenge',
      sub {
        return $fixed_challenge;
      }
    );
  }
}

1;

=head1 NAME

Overnet::Test::ClientInteropHooks - Test-time IRC client interop hooks

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  perl -MOvernet::Test::ClientInteropHooks script.pl

=head1 DESCRIPTION

Applies process-local test hooks used by relay IRC client interoperability
tests.

=head1 SUBROUTINES/METHODS

This module has no public methods. Loading it installs the configured test
hook when C<OVERNET_FIXED_AUTH_CHALLENGE> is present.

=head1 DIAGNOSTICS

This module does not emit diagnostics directly.

=head1 CONFIGURATION AND ENVIRONMENT

C<OVERNET_FIXED_AUTH_CHALLENGE> fixes the authoritative IRC auth challenge for
interop tests.

=head1 DEPENDENCIES

Requires L<Package::Stash> and the IRC server implementation.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/relay-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
