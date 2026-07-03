use strictures 2;

use File::Spec;
use FindBin;
use IPC::Open3 qw(open3);
use Symbol     qw(gensym);
use Test2::V0;

sub _run_help {
  my (@command) = @_;
  my $stderr    = gensym();
  my $pid       = open3(undef, my $stdout, $stderr, @command, '--help',);

  my $stdout_text = do { local $/ = undef; <$stdout> };
  my $stderr_text = do { local $/ = undef; <$stderr> };
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
  local $/ = undef;
  return <$fh>;
}

my $code_root    = File::Spec->catdir($FindBin::Bin, '..');
my $project_root = File::Spec->catdir($code_root,    '..');
my $irc_root     = File::Spec->catdir($project_root, 'irc-server');

my $relay_service_script = File::Spec->catfile($code_root, 'bin',    'overnet-relay-service.pl');
my $irc_command          = File::Spec->catfile($irc_root,  'bin',    'overnet-irc-server');
my $relay_unit           = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay.service');
my $relay_env            = File::Spec->catfile($code_root, 'deploy', 'systemd', 'overnet-relay.env.example');
my $irc_unit             = File::Spec->catfile($irc_root,  'deploy', 'systemd', 'overnet-irc.service');
my $irc_env              = File::Spec->catfile($irc_root,  'deploy', 'systemd', 'overnet-irc.env.example');

ok -f $relay_service_script, 'relay service wrapper exists';
ok -f $irc_command,          'IRC command exists';
ok -f $relay_unit,           'relay systemd unit exists';
ok -f $relay_env,            'relay environment example exists';
ok -f $irc_unit,             'IRC systemd unit exists';
ok -f $irc_env,              'IRC environment example exists';

my $relay_help = _run_help($^X, $relay_service_script);
is $relay_help->{exit_code}, 0, 'relay service wrapper help exits cleanly';
like $relay_help->{stdout}, qr/--health-file\b/mx,    'relay service wrapper exposes --health-file';
like $relay_help->{stdout}, qr/--log-file\b/mx,       'relay service wrapper exposes --log-file';
like $relay_help->{stdout}, qr/--store-file\b/mx,     'relay service wrapper exposes --store-file';
like $relay_help->{stdout}, qr/--service-policy\b/mx, 'relay service wrapper exposes service-policy controls';

my $irc_help = _run_help($^X, $irc_command, 'service');
is $irc_help->{exit_code}, 0, 'IRC service wrapper help exits cleanly';
like $irc_help->{stdout}, qr/--health-file\b/mx, 'IRC service wrapper exposes --health-file';
like $irc_help->{stdout}, qr/--log-file\b/mx,    'IRC service wrapper exposes --log-file';
like $irc_help->{stdout}, qr/--tls\b/mx,         'IRC service wrapper exposes TLS controls';
like $irc_help->{stdout}, qr/--authority-relay-url\b/mx,
  'IRC service wrapper exposes authoritative relay configuration';

my $relay_unit_text = _slurp($relay_unit);
like $relay_unit_text, qr/ExecStart=.*overnet-relay-service\.pl/mx, 'relay unit runs the relay service wrapper';
like $relay_unit_text, qr/EnvironmentFile=.*overnet-relay\.env/mx,  'relay unit uses an environment file';
like $relay_unit_text, qr/--health-file/mx,                         'relay unit configures a health file';
like $relay_unit_text, qr/--log-file/mx,                            'relay unit configures a log file';

my $irc_unit_text = _slurp($irc_unit);
like $irc_unit_text, qr/ExecStart=.*overnet-irc-server\s+service/mx, 'IRC unit runs the IRC service wrapper';
like $irc_unit_text, qr/EnvironmentFile=.*overnet-irc\.env/mx,  'IRC unit uses an environment file';
like $irc_unit_text, qr/--health-file/mx,                       'IRC unit configures a health file';
like $irc_unit_text, qr/--log-file/mx,                          'IRC unit configures a log file';

my $relay_env_text = _slurp($relay_env);
like $relay_env_text, qr/OVERNET_RELAY_STORE_FILE=/mx,             'relay env example exposes store path';
like $relay_env_text, qr/OVERNET_RELAY_LOG_FILE=/mx,               'relay env example exposes log path';
like $relay_env_text, qr/OVERNET_RELAY_HEALTH_FILE=/mx,            'relay env example exposes health path';
like $relay_env_text, qr/OVERNET_RELAY_SERVICE_POLICY_PUBLISH=/mx, 'relay env example exposes publish policy';

my $irc_env_text = _slurp($irc_env);
like $irc_env_text, qr/OVERNET_IRC_SIGNING_KEY_FILE=/mx,    'IRC env example exposes signing key path';
like $irc_env_text, qr/OVERNET_IRC_TLS_CERT_CHAIN_FILE=/mx, 'IRC env example exposes TLS cert path';
like $irc_env_text, qr/OVERNET_IRC_LOG_FILE=/mx,            'IRC env example exposes log path';
like $irc_env_text, qr/OVERNET_IRC_HEALTH_FILE=/mx,         'IRC env example exposes health path';
like $irc_env_text, qr/OVERNET_IRC_AUTHORITY_RELAY_URL=/mx, 'IRC env example exposes authoritative relay URL';

done_testing;
