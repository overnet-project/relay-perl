use strict;
use warnings;

use File::Spec;
use FindBin;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use Test::More;

sub _run_help {
  my (@command) = @_;
  my $stderr = gensym();
  my $pid = open3(
    undef,
    my $stdout,
    $stderr,
    @command,
    '--help',
  );

  my $stdout_text = do { local $/; <$stdout> };
  my $stderr_text = do { local $/; <$stderr> };
  close $stdout;
  close $stderr;
  waitpid($pid, 0);

  return {
    exit_code => $? >> 8,
    stdout    => $stdout_text,
    stderr    => $stderr_text,
  };
}

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

my $relay_service_script = File::Spec->catfile($code_root, 'bin', 'overnet-relay-service.pl');
my $irc_service_script = File::Spec->catfile($irc_root, 'bin', 'overnet-irc-service.pl');
my $relay_unit = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay.service');
my $relay_env = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay.env.example');
my $irc_unit = File::Spec->catfile($irc_root, 'deploy', 'systemd', 'overnet-irc.service');
my $irc_env = File::Spec->catfile($irc_root, 'deploy', 'systemd', 'overnet-irc.env.example');

ok -f $relay_service_script, 'relay service wrapper exists';
ok -f $irc_service_script, 'IRC service wrapper exists';
ok -f $relay_unit, 'relay systemd unit exists';
ok -f $relay_env, 'relay environment example exists';
ok -f $irc_unit, 'IRC systemd unit exists';
ok -f $irc_env, 'IRC environment example exists';

my $relay_help = _run_help($^X, $relay_service_script);
is $relay_help->{exit_code}, 0, 'relay service wrapper help exits cleanly';
like $relay_help->{stdout}, qr/--health-file\b/, 'relay service wrapper exposes --health-file';
like $relay_help->{stdout}, qr/--log-file\b/, 'relay service wrapper exposes --log-file';
like $relay_help->{stdout}, qr/--store-file\b/, 'relay service wrapper exposes --store-file';
like $relay_help->{stdout}, qr/--service-policy\b/, 'relay service wrapper exposes service-policy controls';

my $irc_help = _run_help($^X, $irc_service_script);
is $irc_help->{exit_code}, 0, 'IRC service wrapper help exits cleanly';
like $irc_help->{stdout}, qr/--health-file\b/, 'IRC service wrapper exposes --health-file';
like $irc_help->{stdout}, qr/--log-file\b/, 'IRC service wrapper exposes --log-file';
like $irc_help->{stdout}, qr/--tls\b/, 'IRC service wrapper exposes TLS controls';
like $irc_help->{stdout}, qr/--authority-relay-url\b/, 'IRC service wrapper exposes authoritative relay configuration';

my $relay_unit_text = _slurp($relay_unit);
like $relay_unit_text, qr/ExecStart=.*overnet-relay-service\.pl/, 'relay unit runs the relay service wrapper';
like $relay_unit_text, qr/EnvironmentFile=.*overnet-relay\.env/, 'relay unit uses an environment file';
like $relay_unit_text, qr/--health-file/, 'relay unit configures a health file';
like $relay_unit_text, qr/--log-file/, 'relay unit configures a log file';

my $irc_unit_text = _slurp($irc_unit);
like $irc_unit_text, qr/ExecStart=.*overnet-irc-service\.pl/, 'IRC unit runs the IRC service wrapper';
like $irc_unit_text, qr/EnvironmentFile=.*overnet-irc\.env/, 'IRC unit uses an environment file';
like $irc_unit_text, qr/--health-file/, 'IRC unit configures a health file';
like $irc_unit_text, qr/--log-file/, 'IRC unit configures a log file';

my $relay_env_text = _slurp($relay_env);
like $relay_env_text, qr/OVERNET_RELAY_STORE_FILE=/, 'relay env example exposes store path';
like $relay_env_text, qr/OVERNET_RELAY_LOG_FILE=/, 'relay env example exposes log path';
like $relay_env_text, qr/OVERNET_RELAY_HEALTH_FILE=/, 'relay env example exposes health path';
like $relay_env_text, qr/OVERNET_RELAY_SERVICE_POLICY_PUBLISH=/, 'relay env example exposes publish policy';

my $irc_env_text = _slurp($irc_env);
like $irc_env_text, qr/OVERNET_IRC_SIGNING_KEY_FILE=/, 'IRC env example exposes signing key path';
like $irc_env_text, qr/OVERNET_IRC_TLS_CERT_CHAIN_FILE=/, 'IRC env example exposes TLS cert path';
like $irc_env_text, qr/OVERNET_IRC_LOG_FILE=/, 'IRC env example exposes log path';
like $irc_env_text, qr/OVERNET_IRC_HEALTH_FILE=/, 'IRC env example exposes health path';
like $irc_env_text, qr/OVERNET_IRC_AUTHORITY_RELAY_URL=/, 'IRC env example exposes authoritative relay URL';

done_testing;
