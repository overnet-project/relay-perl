package Overnet::Test::ClientInteropHooks;

use strict;
use warnings;

our $VERSION = '0.001';

BEGIN {
  return unless defined($ENV{OVERNET_FIXED_AUTH_CHALLENGE})
    && !ref($ENV{OVERNET_FIXED_AUTH_CHALLENGE})
    && length($ENV{OVERNET_FIXED_AUTH_CHALLENGE});

  require Overnet::Program::IRC::Server;
  no warnings 'redefine';
  *Overnet::Program::IRC::Server::_generate_authoritative_auth_challenge = sub {
    return $ENV{OVERNET_FIXED_AUTH_CHALLENGE};
  };
}

1;
