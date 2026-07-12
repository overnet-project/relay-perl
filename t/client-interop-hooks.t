use strictures 2;

use Test2::V0;

# Overnet::Test::ClientInteropHooks does all of its work in a BEGIN block
# driven by OVERNET_FIXED_AUTH_CHALLENGE, so this process loads the module
# exactly once with the hook environment set. The disabled scenarios live in
# t/client-interop-hooks-disabled.t, which loads the module without a usable
# challenge value in its own process.
subtest 'loading with OVERNET_FIXED_AUTH_CHALLENGE fixes the challenge' => sub {
  local $ENV{OVERNET_FIXED_AUTH_CHALLENGE} = 'fixed-challenge-for-tests';

  ok eval { require Overnet::Test::ClientInteropHooks; 1 },
    'module loads with the environment variable set';
  ok $INC{'Overnet/Program/IRC/Server.pm'}, 'the IRC server implementation is loaded';
  is(Overnet::Program::IRC::Server::_generate_authoritative_auth_challenge(),
    'fixed-challenge-for-tests',
    'the authoritative auth challenge is replaced with the fixed value');
};

done_testing;
