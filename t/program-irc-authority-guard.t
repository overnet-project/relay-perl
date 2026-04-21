use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

require Overnet::Program::IRC::Server;

{
  package Local::AuthoritativeEmptyReadServer;
  our @ISA = ('Overnet::Program::IRC::Server');

  sub _read_authoritative_nip29_events {
    return [];
  }

  sub _authority_relay_enabled {
    return 1;
  }
}

subtest 'known hosted channels are not silently recreated from empty authoritative reads' => sub {
  my $server = bless {
    config => {
      server_name    => 'overnet.irc.local',
      network        => 'irc.example.test',
      adapter_config => {
        authority_profile => 'nip29',
        group_host        => 'groups.example.test',
      },
    },
    authoritative_discovered_channels => {
      '#overnet' => {
        channel_name => '#overnet',
        group_id     => 'overnet',
      },
    },
  }, 'Local::AuthoritativeEmptyReadServer';

  my $result = $server->_authoritative_join_admission_for_client(
    '#overnet',
    {
      authority_pubkey => 'a' x 64,
      nick             => 'alice',
      username         => 'alice',
      peerhost         => '127.0.0.1',
    },
  );

  ok !$result->{allowed}, 'empty authoritative reads do not silently allow JOIN for a known hosted channel';
  ok !$result->{create_channel}, 'empty authoritative reads do not silently widen into channel creation';
  ok !$result->{auth_required}, 'the known hosted-channel denial is not treated as missing auth';
};

subtest 'local transient channel state does not make a hosted channel authoritative-known' => sub {
  my $server = bless {
    config => {
      server_name    => 'overnet.irc.local',
      network        => 'irc.example.test',
      adapter_config => {
        authority_profile => 'nip29',
        group_host        => 'groups.example.test',
      },
    },
    channels => {
      '#fresh' => {
        channel_name => '#Fresh',
      },
    },
  }, 'Local::AuthoritativeEmptyReadServer';

  my $result = $server->_authoritative_join_admission_for_client(
    '#Fresh',
    {
      authority_pubkey => 'b' x 64,
      nick             => 'alice',
      username         => 'alice',
      peerhost         => '127.0.0.1',
    },
  );

  ok $result->{allowed}, 'transient local channel state does not block authoritative channel creation';
  ok $result->{create_channel}, 'transient local channel state still allows authoritative creation';
  ok !$result->{auth_required}, 'authenticated creation is not treated as missing auth';
};

done_testing;
