use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

use_ok('Overnet::Program::IRC::Command::Auth');

can_ok(
  'Overnet::Program::IRC::Command::Auth',
  qw(
    handle_cap
    handle_authenticate
    handle_overnetauth
    start_sasl_nostr_exchange
    complete_sasl_exchange
    reset_sasl_state
    apply_authoritative_auth_validation
    clear_authoritative_binding
    set_authoritative_account
    ensure_authoritative_delegate_offer
    accept_authoritative_delegate_event
  ),
);

{
  package Local::MockAuthCommandServer;

  sub new {
    return bless {
      called => [],
      config => {
        server_name => 'irc.example.test',
      },
      clients => {
        1 => {
          id         => 1,
          registered => 0,
          nick       => 'alice',
        },
      },
    }, shift;
  }

  sub called {
    return $_[0]{called};
  }

  sub _supported_capabilities {
    return ('message-tags', 'server-time', 'account-tag', 'account-notify', 'overnet-e2ee', 'sasl');
  }

  sub _send_client_line {
    my ($self, $client_id, $line) = @_;
    push @{$self->{called}}, [ client_line => $client_id, $line ];
    return 1;
  }

  sub _register_client_if_ready {
    my ($self, $client) = @_;
    push @{$self->{called}}, [ register => $client->{id} ];
    return 1;
  }

  sub _generate_authoritative_auth_challenge {
    my ($self, $client) = @_;
    push @{$self->{called}}, [ challenge => $client->{id} ];
    return 'a' x 64;
  }

  sub _send_server_notice {
    my ($self, $client_id, $text) = @_;
    push @{$self->{called}}, [ notice => $client_id, $text ];
    return 1;
  }
}

my $mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['LS']),
  'auth command module handles CAP delegation',
);
is_deeply(
  $mock->called,
  [
    [ client_line => 1, ':irc.example.test CAP * LS :message-tags server-time account-tag account-notify overnet-e2ee sasl' ],
  ],
  'CAP delegation preserves capability advertisement rendering',
);

is_deeply(
  [ Local::MockAuthCommandServer->new->_supported_capabilities ],
  [ 'message-tags', 'server-time', 'account-tag', 'account-notify', 'overnet-e2ee', 'sasl' ],
  'mock capability order matches the server capability order used by compatibility tests',
);

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['REQ', 'server-time']),
  'auth command module handles CAP REQ delegation for server-time',
);
is_deeply(
  $mock->called,
  [
    [ client_line => 1, ':irc.example.test CAP * ACK :server-time' ],
  ],
  'CAP REQ acknowledges server-time',
);
ok($mock->{clients}{1}{capabilities}{'server-time'}, 'server-time capability is enabled');
ok($mock->{clients}{1}{capabilities}{'message-tags'}, 'server-time also enables message-tags');

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['REQ', 'account-tag']),
  'auth command module handles CAP REQ delegation for account-tag',
);
is_deeply(
  $mock->called,
  [
    [ client_line => 1, ':irc.example.test CAP * ACK :account-tag' ],
  ],
  'account-tag is ACKed when the capability is advertised',
);
ok($mock->{clients}{1}{capabilities}{'account-tag'}, 'account-tag capability is enabled');
ok($mock->{clients}{1}{capabilities}{'message-tags'}, 'account-tag also enables message-tags');

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($mock, 1, ['CHALLENGE']),
  'auth command module handles OVERNETAUTH challenge delegation',
);
is_deeply(
  $mock->called,
  [
    [ challenge => 1 ],
    [ notice => 1, 'OVERNETAUTH CHALLENGE ' . ('a' x 64) ],
  ],
  'OVERNETAUTH challenge delegation preserves the server notice path',
);

my $server_path = File::Spec->catfile(
  $FindBin::Bin,
  '..',
  '..',
  'overnet-program-irc',
  'lib',
  'Overnet',
  'Program',
  'IRC',
  'Server.pm',
);
open my $server_fh, '<', $server_path
  or die "Unable to read $server_path: $!";
my $server_source = do { local $/; <$server_fh> };
close $server_fh;

like $server_source, qr/use Overnet::Program::IRC::Command::Auth;/,
  'Server.pm loads the focused auth command module';
like $server_source, qr/Overnet::Program::IRC::Command::Auth::handle_cap/,
  'Server.pm delegates CAP handling to the auth command module';
like $server_source, qr/Overnet::Program::IRC::Command::Auth::handle_authenticate/,
  'Server.pm delegates AUTHENTICATE handling to the auth command module';
like $server_source, qr/Overnet::Program::IRC::Command::Auth::handle_overnetauth/,
  'Server.pm delegates OVERNETAUTH handling to the auth command module';
unlike $server_source, qr/\nsub _handle_cap_command \{/,
  'Server.pm no longer defines CAP handling inline';
unlike $server_source, qr/\nsub _handle_authenticate_command \{/,
  'Server.pm no longer defines AUTHENTICATE handling inline';
unlike $server_source, qr/\nsub _start_sasl_nostr_exchange \{/,
  'Server.pm no longer defines SASL challenge state transitions inline';
unlike $server_source, qr/\nsub _complete_sasl_exchange \{/,
  'Server.pm no longer defines SASL completion inline';
unlike $server_source, qr/\nsub _reset_sasl_state \{/,
  'Server.pm no longer defines SASL reset inline';
unlike $server_source, qr/\nsub _apply_authoritative_auth_validation \{/,
  'Server.pm no longer defines authoritative auth binding inline';
unlike $server_source, qr/\nsub _clear_authoritative_binding \{/,
  'Server.pm no longer defines authoritative auth clearing inline';
unlike $server_source, qr/\nsub _ensure_authoritative_delegate_offer \{/,
  'Server.pm no longer defines delegation offer state inline';
unlike $server_source, qr/\nsub _accept_authoritative_delegate_event \{/,
  'Server.pm no longer defines delegation acceptance inline';

done_testing;
