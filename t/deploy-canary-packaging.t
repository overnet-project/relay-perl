use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/;
  return <$fh>;
}

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $project_root = File::Spec->catdir($code_root, '..');
my $irc_root = File::Spec->catdir($project_root, 'overnet-program-irc');

my $authority_relay_service_script = File::Spec->catfile($irc_root, 'bin', 'overnet-irc-authority-relay-service.pl');
my $relay_sync_unit = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay-sync@.service');
my $relay_sync_timer = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay-sync@.timer');
my $authority_relay_unit = File::Spec->catfile($irc_root, 'deploy', 'systemd', 'overnet-irc-authority-relay@.service');
my $templated_irc_unit = File::Spec->catfile($irc_root, 'deploy', 'systemd', 'overnet-irc@.service');

my $code_canary_readme = File::Spec->catfile($code_root, 'deploy', 'canary', 'README.md');
my $code_canary_sync_a_env = File::Spec->catfile($code_root, 'deploy', 'canary', 'relay-sync-a-to-b', 'overnet-relay-sync.env.example');
my $code_canary_sync_a_config = File::Spec->catfile($code_root, 'deploy', 'canary', 'relay-sync-a-to-b', 'relay-sync.json.example');
my $code_canary_sync_b_env = File::Spec->catfile($code_root, 'deploy', 'canary', 'relay-sync-b-to-a', 'overnet-relay-sync.env.example');
my $code_canary_sync_b_config = File::Spec->catfile($code_root, 'deploy', 'canary', 'relay-sync-b-to-a', 'relay-sync.json.example');

my $irc_canary_readme = File::Spec->catfile($irc_root, 'deploy', 'canary', 'README.md');
my $relay_a_env = File::Spec->catfile($irc_root, 'deploy', 'canary', 'relay-a', 'overnet-irc-authority-relay.env.example');
my $relay_b_env = File::Spec->catfile($irc_root, 'deploy', 'canary', 'relay-b', 'overnet-irc-authority-relay.env.example');
my $irc_env = File::Spec->catfile($irc_root, 'deploy', 'canary', 'irc', 'overnet-irc.env.example');

ok -f $authority_relay_service_script, 'authoritative IRC relay service wrapper exists';
ok -f $relay_sync_unit, 'templated relay-sync systemd unit exists';
ok -f $relay_sync_timer, 'templated relay-sync systemd timer exists';
ok -f $authority_relay_unit, 'templated authoritative relay unit exists';
ok -f $templated_irc_unit, 'templated IRC unit exists';

ok -f $code_canary_readme, 'code repo canary README exists';
ok -f $code_canary_sync_a_env, 'canary sync A->B env example exists';
ok -f $code_canary_sync_a_config, 'canary sync A->B config example exists';
ok -f $code_canary_sync_b_env, 'canary sync B->A env example exists';
ok -f $code_canary_sync_b_config, 'canary sync B->A config example exists';

ok -f $irc_canary_readme, 'IRC repo canary README exists';
ok -f $relay_a_env, 'canary relay A env example exists';
ok -f $relay_b_env, 'canary relay B env example exists';
ok -f $irc_env, 'canary IRC env example exists';

my $sync_unit_text = _slurp($relay_sync_unit);
like $sync_unit_text, qr/ExecStart=.*overnet-relay-sync\.pl/, 'relay-sync unit runs the sync CLI';
like $sync_unit_text, qr/EnvironmentFile=.*overnet-relay-sync\.env/, 'relay-sync unit uses a sync env file';

my $sync_timer_text = _slurp($relay_sync_timer);
like $sync_timer_text, qr/OnUnitActiveSec=/, 'relay-sync timer defines a recurring interval';

my $authority_relay_unit_text = _slurp($authority_relay_unit);
like $authority_relay_unit_text, qr/ExecStart=.*overnet-irc-authority-relay-service\.pl/, 'authoritative relay unit runs the authority relay service wrapper';
like $authority_relay_unit_text, qr/EnvironmentFile=.*overnet-irc-authority-relay\.env/, 'authoritative relay unit uses an env file';
like $authority_relay_unit_text, qr/--health-file/, 'authoritative relay unit configures a health file';

my $templated_irc_unit_text = _slurp($templated_irc_unit);
like $templated_irc_unit_text, qr/ExecStart=.*overnet-irc-service\.pl/, 'templated IRC unit runs the IRC service wrapper';
like $templated_irc_unit_text, qr/EnvironmentFile=.*overnet-irc\.env/, 'templated IRC unit uses an env file';

for my $doc (
  [ 'code canary README', _slurp($code_canary_readme) ],
  [ 'IRC canary README',  _slurp($irc_canary_readme) ],
) {
  my ($label, $text) = @{$doc};
  like $text, qr/two relays/i, "$label describes the two-relay topology";
  like $text, qr/one IRC server/i, "$label describes the single IRC server topology";
  like $text, qr/health/i, "$label documents health files or checks";
}

like _slurp($code_canary_sync_a_config), qr/relay-sync-a-to-b|remote_url|local_url/s,
  'sync A->B config example describes the local and remote relay endpoints';
like _slurp($code_canary_sync_b_config), qr/relay-sync-b-to-a|remote_url|local_url/s,
  'sync B->A config example describes the local and remote relay endpoints';

like _slurp($relay_a_env), qr/OVERNET_IRC_AUTHORITY_RELAY_STORE_FILE=/,
  'relay A env example exposes a persisted store path';
like _slurp($relay_b_env), qr/OVERNET_IRC_AUTHORITY_RELAY_STORE_FILE=/,
  'relay B env example exposes a persisted store path';
like _slurp($irc_env), qr/OVERNET_IRC_AUTHORITY_RELAY_URL=/,
  'canary IRC env example points at an authority relay URL';

done_testing;
