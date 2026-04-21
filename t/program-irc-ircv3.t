use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

use_ok('Overnet::Program::IRC::Server');
use_ok('Overnet::Program::IRC::Command::Auth');

{
  my $server = Overnet::Program::IRC::Server->new;
  $server->{config}{adapter_config}{authority_profile} = 'nip29';
  is_deeply(
    [ $server->_supported_capabilities ],
    [ qw(message-tags server-time overnet-e2ee account-tag account-notify sasl) ],
    'server advertises the IRCv3 message-tags, account, and server-time capabilities',
  );
}

{
  socketpair(my $server_sock, my $client_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  my $server = Overnet::Program::IRC::Server->new;
  $server->{clients}{1} = {
    id           => 1,
    nick         => 'alice',
    capabilities => {
      'server-time' => 1,
      'message-tags' => 1,
    },
    socket => $server_sock,
  };

  ok(
    $server->_send_client_line(1, ':irc.example.test 001 alice :Welcome to Overnet IRC'),
    'server sends a tagged outbound line for IRCv3 clients',
  );
  my $buffer = '';
  my $read = sysread($client_sock, $buffer, 4096);
  ok($read, 'tagged outbound payload is readable');
  like(
    $buffer,
    qr/\A\@time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z :irc\.example\.test 001 alice :Welcome to Overnet IRC\r\n\z/,
    'server-time tag is prepended to outbound IRC lines',
  );
}

{
  socketpair(my $alice_server_sock, my $alice_client_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  my $server = Overnet::Program::IRC::Server->new;
  $server->{clients}{1} = {
    id           => 1,
    nick         => 'alice',
    capabilities => {
      'message-tags' => 1,
      'account-tag'  => 1,
    },
    socket => $alice_server_sock,
  };
  $server->{clients}{2} = {
    id               => 2,
    nick             => 'bob',
    authority_pubkey => ('b' x 64),
  };
  $server->{nick_to_client_id}{ $server->_nick_key('alice') } = 1;
  $server->{nick_to_client_id}{ $server->_nick_key('bob') } = 2;

  ok(
    $server->_send_client_line(1, ':bob PRIVMSG #overnet :Hello from Bob'),
    'server sends an outbound line from an authenticated sender',
  );
  my $buffer = '';
  my $read = sysread($alice_client_sock, $buffer, 4096);
  ok($read, 'tagged account payload is readable');
  is(
    $buffer,
    '@account=' . ('b' x 64) . " :bob PRIVMSG #overnet :Hello from Bob\r\n",
    'account-tag is prepended for authenticated senders',
  );
}

{
  socketpair(my $server_sock, my $client_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  my $server = Overnet::Program::IRC::Server->new;
  $server->{clients}{1} = {
    id           => 1,
    nick         => 'alice',
    capabilities => {},
    socket       => $server_sock,
  };

  ok(
    $server->_send_client_line(1, ':irc.example.test 001 alice :Welcome to Overnet IRC'),
    'server sends an untagged outbound line when no IRCv3 tag capability is enabled',
  );
  my $buffer = '';
  my $read = sysread($client_sock, $buffer, 4096);
  ok($read, 'untagged outbound payload is readable');
  is(
    $buffer,
    ":irc.example.test 001 alice :Welcome to Overnet IRC\r\n",
    'outbound lines stay untagged for clients without IRCv3 tag capabilities',
  );
}

{
  socketpair(my $requester_server_sock, my $requester_client_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  my $server = Overnet::Program::IRC::Server->new;
  $server->{config}{server_name} = 'irc.example.test';
  $server->{clients}{1} = {
    id           => 1,
    registered   => 1,
    nick         => 'alice',
    username     => 'alice',
    realname     => 'Alice',
    capabilities => {},
    socket       => $requester_server_sock,
  };
  $server->{clients}{2} = {
    id                => 2,
    registered        => 1,
    nick              => 'bob',
    username          => 'bob',
    realname          => 'Bob',
    authority_pubkey  => ('b' x 64),
    capabilities      => {},
    socket            => undef,
    peerhost          => '127.0.0.1',
  };
  $server->{nick_to_client_id}{ $server->_nick_key('alice') } = 1;
  $server->{nick_to_client_id}{ $server->_nick_key('bob') } = 2;

  my $entry = $server->_whois_entry_for_nick('bob');
  ok($entry, 'WHOIS entry exists for an authenticated user');
  is($entry->{account}, ('b' x 64), 'WHOIS entry carries the authenticated account identity');

  ok($server->_send_whois_reply(1, $entry), 'WHOIS reply renders successfully');
  my $buffer = '';
  my $read = sysread($requester_client_sock, $buffer, 4096);
  ok($read, 'WHOIS reply payload is readable');
  like(
    $buffer,
    qr/\Q:irc.example.test 330 alice bob \E[b]{64}\Q :is logged in as\E/,
    'WHOIS reply includes the authenticated account identity',
  );
}

{
  socketpair(my $alice_server_sock, my $alice_client_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  my $server = Overnet::Program::IRC::Server->new;
  $server->{clients}{1} = {
    id           => 1,
    registered   => 1,
    nick         => 'alice',
    username     => 'alice',
    capabilities => {
      'account-notify' => 1,
    },
    joined_channels => {
      '#overnet' => '#overnet',
    },
    socket       => $alice_server_sock,
  };
  $server->{clients}{2} = {
    id              => 2,
    registered      => 1,
    nick            => 'bob',
    username        => 'bob',
    joined_channels => {
      '#overnet' => '#overnet',
    },
    socket          => undef,
    peerhost        => '127.0.0.1',
  };
  $server->{nick_to_client_id}{ $server->_nick_key('alice') } = 1;
  $server->{nick_to_client_id}{ $server->_nick_key('bob') } = 2;
  $server->_channel_state('#overnet')->{members}{1} = 1;
  $server->_channel_state('#overnet')->{members}{2} = 1;
  $server->_add_visible_nick('#overnet', 'alice');
  $server->_add_visible_nick('#overnet', 'bob');

  ok(
    Overnet::Program::IRC::Command::Auth::set_authoritative_account(
      $server,
      $server->{clients}{2},
      account => ('b' x 64),
    ),
    'setting an authenticated account succeeds',
  );
  my $buffer = '';
  my $read = sysread($alice_client_sock, $buffer, 4096);
  ok($read, 'account-notify payload is readable');
  is(
    $buffer,
    ':bob!bob@127.0.0.1 ACCOUNT ' . ('b' x 64) . "\r\n",
    'shared channel peers receive ACCOUNT login notifications',
  );
}

done_testing;
