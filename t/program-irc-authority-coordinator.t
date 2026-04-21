use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc', 'lib');

use_ok('Overnet::Program::IRC::Authority::Coordinator');

can_ok(
  'Overnet::Program::IRC::Authority::Coordinator',
  qw(
    authoritative_grant_subscription_id
    authoritative_discovery_subscription_id
    authoritative_channel_subscription_ids
    ensure_authoritative_grant_subscription
    ensure_authoritative_discovery_subscription
    ensure_authoritative_channel_subscription
    read_authoritative_nip29_events
    read_authoritative_grant_events
    publish_authoritative_nip29_event
    handle_subscription_event
  ),
);

{
  package Local::MockAuthorityCoordinatorServer;

  sub new {
    return bless {
      config => {
        network => 'example.test',
      },
      authoritative_grant_subscription_id => undef,
      called => [],
    }, shift;
  }

  sub called {
    return $_[0]{called};
  }

  sub _authority_relay_enabled {
    return 1;
  }

  sub _authority_relay_url {
    return 'wss://relay.example.test';
  }

  sub _authority_relay_query_timeout_ms {
    return 1500;
  }

  sub _authority_grant_kind {
    return 14142;
  }

  sub _request {
    my ($self, %args) = @_;
    push @{$self->{called}}, \%args;
    return { events => [] };
  }

  sub _authoritative_group_binding {
    return ('groups.example.test', 'ops');
  }

  sub _canonical_channel_name {
    return $_[1];
  }
}

my $mock = Local::MockAuthorityCoordinatorServer->new;

is(
  Overnet::Program::IRC::Authority::Coordinator::authoritative_grant_subscription_id($mock),
  'irc.authority.grants:example.test',
  'coordinator derives the grant subscription id from the network',
);

is_deeply(
  [
    Overnet::Program::IRC::Authority::Coordinator::authoritative_channel_subscription_ids(
      $mock,
      '#ops',
    )
  ],
  [
    'irc.authority.meta:example.test:groups.example.test:ops',
    'irc.authority.control:example.test:groups.example.test:ops',
  ],
  'coordinator derives deterministic authoritative channel subscription ids',
);

is(
  Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_grant_subscription($mock),
  'irc.authority.grants:example.test',
  'coordinator opens the authoritative grant subscription',
);
is_deeply(
  $mock->called,
  [
    {
      method => 'nostr.open_subscription',
      params => {
        subscription_id => 'irc.authority.grants:example.test',
        relay_url       => 'wss://relay.example.test',
        timeout_ms      => 1500,
        filters         => [
          {
            kinds => [14142],
            limit => 200,
          },
        ],
      },
    },
  ],
  'grant subscription coordination goes through the runtime Nostr service',
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

like $server_source, qr/use Overnet::Program::IRC::Authority::Coordinator;/,
  'Server.pm loads the authority coordinator module';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_grant_subscription/,
  'Server.pm delegates authoritative grant subscriptions to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_discovery_subscription/,
  'Server.pm delegates authoritative discovery subscriptions to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_channel_subscription/,
  'Server.pm delegates authoritative channel subscriptions to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::read_authoritative_nip29_events/,
  'Server.pm delegates authoritative event reads to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::read_authoritative_grant_events/,
  'Server.pm delegates authoritative grant reads to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::publish_authoritative_nip29_event/,
  'Server.pm delegates authoritative relay publishes to the coordinator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event/,
  'Server.pm delegates runtime subscription events to the coordinator';
unlike $server_source, qr/method => 'nostr\.open_subscription'/,
  'Server.pm no longer embeds raw nostr.open_subscription calls';
unlike $server_source, qr/method => 'nostr\.read_subscription_snapshot'/,
  'Server.pm no longer embeds raw nostr.read_subscription_snapshot calls';
unlike $server_source, qr/method => 'nostr\.query_events'/,
  'Server.pm no longer embeds raw nostr.query_events calls';
unlike $server_source, qr/method => 'nostr\.publish_event'/,
  'Server.pm no longer embeds raw nostr.publish_event calls';

done_testing;
