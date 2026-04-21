use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

use_ok('Overnet::Program::IRC::Renderer');

can_ok(
  'Overnet::Program::IRC::Renderer',
  qw(
    registration_prelude_lines
    list_reply_lines
    names_list_lines
    unknown_command_line
    need_more_params_line
    not_registered_line
    no_such_channel_line
    cannot_send_to_channel_line
    chan_op_privs_needed_line
    cannot_join_channel_line
    ban_list_entry_line
    end_of_ban_list_line
    account_notify_line
    nick_in_use_line
  ),
);

is_deeply(
  Overnet::Program::IRC::Renderer::registration_prelude_lines(
    server_name    => 'overnet.irc.local',
    nick           => 'alice',
    isupport_tokens => 'CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=irc.test',
  ),
  [
    ':overnet.irc.local 001 alice :Welcome to Overnet IRC',
    ':overnet.irc.local 005 alice CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=irc.test :are supported by this server',
    ':overnet.irc.local 422 alice :MOTD File is missing',
  ],
  'renderer formats the registration prelude',
);

is_deeply(
  Overnet::Program::IRC::Renderer::list_reply_lines(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    entries     => [
      {
        channel       => '#overnet',
        visible_users => 2,
        topic         => 'Authoritative topic',
      },
    ],
  ),
  [
    ':overnet.irc.local 321 alice Channel :Users Name',
    ':overnet.irc.local 322 alice #overnet 2 :Authoritative topic',
    ':overnet.irc.local 323 alice :End of /LIST',
  ],
  'renderer formats a LIST response',
);

is_deeply(
  Overnet::Program::IRC::Renderer::names_list_lines(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
    names       => [ '@alice', '+bob' ],
  ),
  [
    ':overnet.irc.local 353 alice = #overnet :@alice +bob',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
  ],
  'renderer formats a NAMES response',
);

is(
  Overnet::Program::IRC::Renderer::ban_list_entry_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
    ban_mask    => '*!*@example.test',
  ),
  ':overnet.irc.local 367 alice #overnet *!*@example.test overnet.irc.local 0',
  'renderer formats a ban-list entry',
);

is(
  Overnet::Program::IRC::Renderer::end_of_ban_list_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
  ),
  ':overnet.irc.local 368 alice #overnet :End of channel ban list',
  'renderer formats an end-of-ban-list line',
);

is(
  Overnet::Program::IRC::Renderer::account_notify_line(
    nick     => 'bob',
    username => 'bob',
    host     => '127.0.0.1',
    account  => ('b' x 64),
  ),
  ':bob!bob@127.0.0.1 ACCOUNT ' . ('b' x 64),
  'renderer formats ACCOUNT login notifications',
);

is(
  Overnet::Program::IRC::Renderer::account_notify_line(
    nick     => 'bob',
    username => 'bob',
    host     => '127.0.0.1',
    account  => undef,
  ),
  ':bob!bob@127.0.0.1 ACCOUNT *',
  'renderer formats ACCOUNT logout notifications',
);

is(
  Overnet::Program::IRC::Renderer::cannot_join_channel_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
    reason      => '+i',
  ),
  ':overnet.irc.local 473 alice #overnet :Cannot join channel (+i)',
  'renderer formats invite-only join rejection',
);

is(
  Overnet::Program::IRC::Renderer::cannot_join_channel_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
    reason      => '+b',
  ),
  ':overnet.irc.local 474 alice #overnet :Cannot join channel (+b)',
  'renderer formats banned join rejection',
);

is(
  Overnet::Program::IRC::Renderer::unknown_command_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    command     => 'FROB',
  ),
  ':overnet.irc.local 421 alice FROB :Unknown command',
  'renderer formats unknown-command numeric replies',
);

is(
  Overnet::Program::IRC::Renderer::need_more_params_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    command     => 'JOIN',
  ),
  ':overnet.irc.local 461 alice JOIN :Not enough parameters',
  'renderer formats need-more-params replies',
);

is(
  Overnet::Program::IRC::Renderer::not_registered_line(
    server_name => 'overnet.irc.local',
  ),
  ':overnet.irc.local 451 * :You have not registered',
  'renderer formats not-registered replies',
);

is(
  Overnet::Program::IRC::Renderer::no_such_channel_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#missing',
  ),
  ':overnet.irc.local 403 alice #missing :No such channel',
  'renderer formats no-such-channel replies',
);

is(
  Overnet::Program::IRC::Renderer::cannot_send_to_channel_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
  ),
  ':overnet.irc.local 404 alice #overnet :Cannot send to channel',
  'renderer formats cannot-send-to-channel replies',
);

is(
  Overnet::Program::IRC::Renderer::chan_op_privs_needed_line(
    server_name => 'overnet.irc.local',
    nick        => 'alice',
    channel     => '#overnet',
  ),
  ':overnet.irc.local 482 alice #overnet :You\'re not channel operator',
  'renderer formats chan-op-privs-needed replies',
);

is(
  Overnet::Program::IRC::Renderer::nick_in_use_line(
    server_name    => 'overnet.irc.local',
    nick           => 'alice',
    attempted_nick => 'Alice',
  ),
  ':overnet.irc.local 433 alice Alice :Nickname is already in use',
  'renderer formats nick-in-use replies',
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

like $server_source, qr/use Overnet::Program::IRC::Renderer;/,
  'Server.pm loads the dedicated IRC renderer module';
unlike $server_source, qr/421 %s %s :Unknown command/,
  'Server.pm no longer formats unknown-command numerics directly';
unlike $server_source, qr/001 %s :Welcome to Overnet IRC/,
  'Server.pm no longer formats registration numerics directly';
unlike $server_source, qr/321 %s Channel :Users Name/,
  'Server.pm no longer formats LIST numerics directly';
unlike $server_source, qr/353 %s = %s :%s/,
  'Server.pm no longer formats NAMES numerics directly';
unlike $server_source, qr/367 %s %s %s %s 0/,
  'Server.pm no longer formats ban-list numerics directly';

done_testing;
