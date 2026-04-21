use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

use_ok('Overnet::Program::IRC::Command::Channel');

can_ok(
  'Overnet::Program::IRC::Command::Channel',
  qw(
    handle_join
    handle_part
    handle_privmsg_or_notice
    handle_topic
    handle_mode
    handle_invite
    handle_kick
    handle_list
    handle_overnetchannel
  ),
);

{
  package Local::MockChannelCommandServer;

  sub new {
    return bless {
      called  => [],
      clients => {
        1 => {
          id         => 1,
          registered => 1,
          nick       => 'alice',
        },
      },
    }, shift;
  }

  sub called {
    return $_[0]{called};
  }

  sub _send_list_reply {
    my ($self, $client_id, $target) = @_;
    push @{$self->{called}}, [ list => $client_id, $target ];
    return 1;
  }

  sub _send_need_more_params {
    my ($self, $client_id, $command) = @_;
    push @{$self->{called}}, [ need_more_params => $client_id, $command ];
    return 1;
  }

  sub _send_unknown_command {
    my ($self, $client_id, $command) = @_;
    push @{$self->{called}}, [ unknown_command => $client_id, $command ];
    return 1;
  }
}

my $mock = Local::MockChannelCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Channel::handle_list($mock, 1, ['#overnet']),
  'channel command module handles LIST delegation',
);
is_deeply(
  $mock->called,
  [
    [ list => 1, '#overnet' ],
  ],
  'LIST delegation calls back into the server list renderer',
);

$mock = Local::MockChannelCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Channel::handle_overnetchannel($mock, 1, []),
  'channel command module handles OVERNETCHANNEL validation',
);
is_deeply(
  $mock->called,
  [
    [ need_more_params => 1, 'OVERNETCHANNEL' ],
  ],
  'OVERNETCHANNEL delegation preserves the existing parameter validation path',
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

like $server_source, qr/use Overnet::Program::IRC::Command::Channel;/,
  'Server.pm loads the focused channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_join/,
  'Server.pm delegates JOIN handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_part/,
  'Server.pm delegates PART handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice/,
  'Server.pm delegates PRIVMSG and NOTICE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_topic/,
  'Server.pm delegates TOPIC handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_mode/,
  'Server.pm delegates MODE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_invite/,
  'Server.pm delegates INVITE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_kick/,
  'Server.pm delegates KICK handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_list/,
  'Server.pm delegates LIST handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_overnetchannel/,
  'Server.pm delegates OVERNETCHANNEL handling to the channel command module';

done_testing;
