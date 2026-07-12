use strictures 2;

use File::Temp qw(tempdir);
use JSON       ();
use Test2::V0;

use Overnet::Relay::Sync::Config;

my $JSON = JSON->new->utf8->canonical;

sub _valid_config {
  my (%overrides) = @_;
  my %config = (
    local_url       => 'ws://127.0.0.1:7448',
    timeout_seconds => 5,
    peers           => [
      {
        name            => 'relay-a',
        remote_url      => 'ws://127.0.0.1:7447',
        subscription_id => 'relay-a-sync',
        filter          => {
          kinds => [37_800],
          '#d'  => ['irc:sync:#overnet'],
        },
      },
    ],
  );
  for my $field (keys %overrides) {
    if (defined $overrides{$field}) {
      $config{$field} = $overrides{$field};
    }
    else {
      delete $config{$field};
    }
  }
  return \%config;
}

sub _write_config_file {
  my ($dir, $name, $raw) = @_;
  my $path = "$dir/$name";
  open my $fh, '>:raw', $path or die "open $path: $!";
  print {$fh} $raw or die "print $path: $!";
  close $fh       or die "close $path: $!";
  return $path;
}

subtest 'load_file loads and normalizes a valid config file' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = _write_config_file($dir, 'sync.json', $JSON->encode(_valid_config()));

  my $config = Overnet::Relay::Sync::Config->load_file($path);

  is $config->{local_url},       'ws://127.0.0.1:7448', 'local_url is preserved';
  is $config->{timeout_seconds}, 5,                     'timeout_seconds is preserved';
  is scalar(@{$config->{peers}}), 1, 'one peer is normalized';

  my $peer = $config->{peers}[0];
  is $peer->{name},            'relay-a',             'peer name is preserved';
  is $peer->{remote_url},      'ws://127.0.0.1:7447', 'peer remote_url is preserved';
  is $peer->{subscription_id}, 'relay-a-sync',        'peer subscription_id is preserved';
  is $peer->{filter_hash},
    {
    kinds => [37_800],
    '#d'  => ['irc:sync:#overnet'],
    },
    'peer filter_hash preserves the raw filter shape';
  isa_ok $peer->{filter}, ['Net::Nostr::Filter'], 'peer filter is a Net::Nostr::Filter';
};

subtest 'load_file rejects missing or invalid path arguments' => sub {
  like dies { Overnet::Relay::Sync::Config->load_file() },
    qr/config\ path\ is\ required/mxs, 'undef path is rejected';
  like dies { Overnet::Relay::Sync::Config->load_file(q{}) },
    qr/config\ path\ is\ required/mxs, 'empty path is rejected';
  like dies { Overnet::Relay::Sync::Config->load_file({}) },
    qr/config\ path\ is\ required/mxs, 'ref path is rejected';
};

subtest 'load_file reports unreadable files and invalid JSON' => sub {
  my $dir = tempdir(CLEANUP => 1);

  like dies { Overnet::Relay::Sync::Config->load_file("$dir/does-not-exist.json") },
    qr/unable\ to\ open\ config\ file/mxs, 'missing file is reported';

  my $path = _write_config_file($dir, 'invalid.json', '{ not json');
  like dies { Overnet::Relay::Sync::Config->load_file($path) },
    qr/invalid\ sync\ config\ JSON\ in/mxs, 'invalid JSON is reported with the path';
};

subtest 'normalize rejects non-object configs and unknown fields' => sub {
  like dies { Overnet::Relay::Sync::Config->normalize(['not', 'a', 'hash']) },
    qr/sync\ config\ must\ be\ a\ JSON\ object/mxs, 'array config is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize('scalar') },
    qr/sync\ config\ must\ be\ a\ JSON\ object/mxs, 'scalar config is rejected';

  my $config = _valid_config();
  $config->{bogus}   = 1;
  $config->{another} = 2;
  like dies { Overnet::Relay::Sync::Config->normalize($config) },
    qr/unknown\ sync\ config\ field\(s\):\ another,\ bogus/mxs,
    'unknown config fields are reported sorted';
};

subtest 'normalize requires local_url' => sub {
  like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(local_url => undef)) },
    qr/sync\ config\ local_url\ is\ required/mxs, 'missing local_url is rejected';
  my $config = _valid_config();
  $config->{local_url} = q{};
  like dies { Overnet::Relay::Sync::Config->normalize($config) },
    qr/sync\ config\ local_url\ is\ required/mxs, 'empty local_url is rejected';
};

subtest 'normalize validates timeout_seconds' => sub {
  my $config = Overnet::Relay::Sync::Config->normalize(_valid_config(timeout_seconds => undef));
  is $config->{timeout_seconds}, 5, 'timeout_seconds defaults to 5';

  $config = Overnet::Relay::Sync::Config->normalize(_valid_config(timeout_seconds => 30));
  is $config->{timeout_seconds}, 30, 'explicit timeout_seconds is kept';

  for my $bad ([], 'abc', '-3', '0', '1.5') {
    like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(timeout_seconds => $bad)) },
      qr/sync\ config\ timeout_seconds\ must\ be\ a\ positive\ integer/mxs,
      'invalid timeout_seconds is rejected: ' . (ref($bad) || $bad);
  }
};

subtest 'normalize validates the peers array' => sub {
  like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(peers => undef)) },
    qr/sync\ config\ peers\ must\ be\ a\ non-empty\ array/mxs, 'missing peers is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(peers => [])) },
    qr/sync\ config\ peers\ must\ be\ a\ non-empty\ array/mxs, 'empty peers is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(peers => {})) },
    qr/sync\ config\ peers\ must\ be\ a\ non-empty\ array/mxs, 'non-array peers is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize(_valid_config(peers => ['scalar'])) },
    qr/sync\ config\ peer\[0\]\ must\ be\ an\ object/mxs, 'non-object peer is rejected by index';
};

subtest 'normalize validates peer fields' => sub {
  my $peer = sub {
    my (%overrides) = @_;
    my $config = _valid_config();
    my %peer   = (%{$config->{peers}[0]}, %overrides);
    for my $field (keys %peer) {
      if (!defined $peer{$field}) {
        delete $peer{$field};
      }
    }
    $config->{peers} = [\%peer];
    return $config;
  };

  like dies { Overnet::Relay::Sync::Config->normalize($peer->(bogus => 1)) },
    qr/unknown\ sync\ peer\[0\]\ field\(s\):\ bogus/mxs, 'unknown peer fields are reported';

  like dies { Overnet::Relay::Sync::Config->normalize($peer->(name => q{})) },
    qr/sync\ config\ peer\[0\]\ name\ must\ be\ a\ non-empty\ string/mxs,
    'empty peer name is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize($peer->(name => {})) },
    qr/sync\ config\ peer\[0\]\ name\ must\ be\ a\ non-empty\ string/mxs,
    'ref peer name is rejected';

  like dies { Overnet::Relay::Sync::Config->normalize($peer->(remote_url => undef)) },
    qr/sync\ config\ peer\[0\]\ remote_url\ is\ required/mxs, 'missing remote_url is rejected';

  like dies { Overnet::Relay::Sync::Config->normalize($peer->(filter => undef)) },
    qr/sync\ config\ peer\[0\]\ filter\ must\ be\ an\ object/mxs, 'missing filter is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize($peer->(filter => [])) },
    qr/sync\ config\ peer\[0\]\ filter\ must\ be\ an\ object/mxs, 'array filter is rejected';
  like dies { Overnet::Relay::Sync::Config->normalize($peer->(filter => {bogus => 1})) },
    qr/invalid\ sync\ config\ peer\[0\]\ filter:/mxs, 'unbuildable filter is rejected';

  my $minimal = Overnet::Relay::Sync::Config->normalize(
    $peer->(name => undef, subscription_id => undef));
  my $normalized_peer = $minimal->{peers}[0];
  ok !exists $normalized_peer->{name},            'omitted name stays omitted';
  ok !exists $normalized_peer->{subscription_id}, 'omitted subscription_id stays omitted';
  is $normalized_peer->{remote_url}, 'ws://127.0.0.1:7447', 'remote_url survives minimal peer';
};

subtest 'normalize rejects duplicate peer names but allows unnamed peers' => sub {
  my $config = _valid_config();
  my %peer   = %{$config->{peers}[0]};
  $config->{peers} = [{%peer}, {%peer, subscription_id => 'relay-a-sync-2'}];
  like dies { Overnet::Relay::Sync::Config->normalize($config) },
    qr/duplicate\ sync\ peer\ name:\ relay-a/mxs, 'duplicate peer names are rejected';

  my %unnamed = %peer;
  delete $unnamed{name};
  $config->{peers} = [{%unnamed}, {%unnamed}];
  my $normalized = Overnet::Relay::Sync::Config->normalize($config);
  is scalar(@{$normalized->{peers}}), 2, 'multiple unnamed peers are allowed';
};

done_testing;
