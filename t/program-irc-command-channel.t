use strictures 2;
use File::Spec;
use FindBin;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');

my $module = 'Overnet::Program::IRC::Command::Channel';
my $path   = $module =~ s{::}{/}gr . '.pm';
my $loaded = eval {
  require $path;
  1;
};
ok $loaded, "$module loads"
  or diag $@;

for my $method (
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
  )
) {
  ok $module->can($method), "$module can $method";
}

{

  package Local::MockChannelCommandServer;

  use Moo;

  has called => (is => 'ro', reader => '_called', default => sub { [] });
  has clients => (
    is      => 'ro',
    default => sub {
      return {
        1 => {
          id         => 1,
          registered => 1,
          nick       => 'alice',
        },
      };
    },
  );

  no Moo;

  sub called {
    return $_[0]{called};
  }

  sub _send_list_reply {
    my ($self, $client_id, $target) = @_;
    push @{$self->{called}}, [list => $client_id, $target];
    return 1;
  }

  sub _send_need_more_params {
    my ($self, $client_id, $command) = @_;
    push @{$self->{called}}, [need_more_params => $client_id, $command];
    return 1;
  }

  sub _send_unknown_command {
    my ($self, $client_id, $command) = @_;
    push @{$self->{called}}, [unknown_command => $client_id, $command];
    return 1;
  }
}

my $mock = Local::MockChannelCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Channel::handle_list($mock, 1, ['#overnet']),
  'channel command module handles LIST delegation',
);
is($mock->called, [[list => 1, '#overnet'],], 'LIST delegation calls back into the server list renderer',);

$mock = Local::MockChannelCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Channel::handle_overnetchannel($mock, 1, []),
  'channel command module handles OVERNETCHANNEL validation',
);
is(
  $mock->called,
  [[need_more_params => 1, 'OVERNETCHANNEL'],],
  'OVERNETCHANNEL delegation preserves the existing parameter validation path',
);

my $server_path =
  File::Spec->catfile($FindBin::Bin, '..', '..', 'irc-server', 'lib', 'Overnet', 'Program', 'IRC', 'Server.pm',);
open my $server_fh, '<', $server_path
  or die "Unable to read $server_path: $!";
my $server_source = do { local $/ = undef; <$server_fh> };
close $server_fh;

like $server_source, qr/use\ Overnet::Program::IRC::Command::Channel;/mx,
  'Server.pm loads the focused channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_join/mx,
  'Server.pm delegates JOIN handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_part/mx,
  'Server.pm delegates PART handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice/mx,
  'Server.pm delegates PRIVMSG and NOTICE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_topic/mx,
  'Server.pm delegates TOPIC handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_mode/mx,
  'Server.pm delegates MODE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_invite/mx,
  'Server.pm delegates INVITE handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_kick/mx,
  'Server.pm delegates KICK handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_list/mx,
  'Server.pm delegates LIST handling to the channel command module';
like $server_source, qr/Overnet::Program::IRC::Command::Channel::handle_overnetchannel/mx,
  'Server.pm delegates OVERNETCHANNEL handling to the channel command module';

done_testing;
