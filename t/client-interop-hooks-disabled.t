use strictures 2;

use Test2::V0;

# Companion to t/client-interop-hooks.t: loading the hooks module without a
# usable OVERNET_FIXED_AUTH_CHALLENGE value must install nothing. This runs in
# its own process because the module's BEGIN block only observes the
# environment on its first load.
subtest 'loading with an empty challenge value installs no hook' => sub {
  local $ENV{OVERNET_FIXED_AUTH_CHALLENGE} = q{};

  ok eval { require Overnet::Test::ClientInteropHooks; 1 },
    'module loads with an empty challenge value';
  ok !$INC{'Overnet/Program/IRC/Server.pm'},
    'the IRC server implementation is not loaded';
};

subtest 'loading without the environment variable installs no hook' => sub {
  local $ENV{OVERNET_FIXED_AUTH_CHALLENGE};
  delete $ENV{OVERNET_FIXED_AUTH_CHALLENGE};

  my $status = system $^X, '-Ilib', '-MOvernet::Test::ClientInteropHooks',
    '-e', 'exit($INC{q{Overnet/Program/IRC/Server.pm}} ? 1 : 0)';
  is $status, 0, 'a fresh process loads the module and skips the IRC server';
};

done_testing;
