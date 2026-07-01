use strictures 2;
use File::Spec;
use FindBin;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');

require Overnet::Program::IRC::Server;

{

  package Local::AuthoritativeEmptyReadServer;

  use Moo;
  extends 'Overnet::Program::IRC::Server';
  no Moo;

  sub _read_authoritative_nip29_events {
    my ($self, $channel, %args) = @_;
    push @{$self->{authoritative_read_calls}},
      {
      channel => $channel,
      args    => {%args},
      };
    return [];
  }

  sub _authority_relay_enabled {
    return 1;
  }
}

subtest 'known hosted channels are not silently recreated from empty authoritative reads' => sub {
  my $server = Local::AuthoritativeEmptyReadServer->new;
  @{$server}{
    qw(
      config
      authoritative_discovered_channels
    )
    }
    = (
    {
      server_name    => 'overnet.irc.local',
      network        => 'irc.example.test',
      adapter_config => {
        authority_profile => 'nip29',
        group_host        => 'groups.example.test',
      },
    },
    {
      '#overnet' => {
        channel_name => '#overnet',
        group_id     => 'overnet',
      },
    },
    );

  my $result = $server->_authoritative_join_admission_for_client(
    '#overnet',
    {
      authority_pubkey => 'a' x 64,
      nick             => 'alice',
      username         => 'alice',
      peerhost         => '127.0.0.1',
    },
  );

  ok !$result->{allowed},        'empty authoritative reads do not silently allow JOIN for a known hosted channel';
  ok !$result->{create_channel}, 'empty authoritative reads do not silently widen into channel creation';
  ok !$result->{auth_required},  'the known hosted-channel denial is not treated as missing auth';
  ok $server->{authoritative_read_calls}[0]{args}{force},
    'uncached relay admission uses a one-shot refresh query before subscribing';
};

subtest 'local transient channel state does not make a hosted channel authoritative-known' => sub {
  my $server = Local::AuthoritativeEmptyReadServer->new;
  @{$server}{
    qw(
      config
      channels
    )
    }
    = (
    {
      server_name    => 'overnet.irc.local',
      network        => 'irc.example.test',
      adapter_config => {
        authority_profile => 'nip29',
        group_host        => 'groups.example.test',
      },
    },
    {
      '#fresh' => {
        channel_name => '#Fresh',
      },
    },
    );

  my $result = $server->_authoritative_join_admission_for_client(
    '#Fresh',
    {
      authority_pubkey => 'b' x 64,
      nick             => 'alice',
      username         => 'alice',
      peerhost         => '127.0.0.1',
    },
  );

  ok $result->{allowed},        'transient local channel state does not block authoritative channel creation';
  ok $result->{create_channel}, 'transient local channel state still allows authoritative creation';
  ok !$result->{auth_required}, 'authenticated creation is not treated as missing auth';
};

done_testing;
