use strict;
use warnings;
use Test::More;
use File::Spec;
use File::Temp qw(tempdir tempfile);
use FindBin;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);
use IPC::Open3 qw(open3);
use JSON::PP qw(decode_json encode_json);
use MIME::Base64 qw(encode_base64);
use Overnet::Core::Nostr;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(sleep time);

my $program_repo = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc');
my $program_path = File::Spec->catfile($program_repo, 'bin', 'overnet-irc-server.pl');
my $irc_lib = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');
my $code_lib = File::Spec->catdir($FindBin::Bin, '..', 'lib');
my $code_local_lib = File::Spec->catdir($FindBin::Bin, '..', 'local', 'lib', 'perl5');

sub _free_port {
  my $sock = IO::Socket::INET->new(
    Listen    => 1,
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Can't allocate free TCP port: $!";

  my $port = $sock->sockport;
  close $sock;
  return $port;
}

sub _shell_quote {
  my ($value) = @_;
  $value = '' unless defined $value;
  $value =~ s/'/'"'"'/g;
  return "'$value'";
}

sub _tcl_quote {
  my ($value) = @_;
  $value = '' unless defined $value;
  $value =~ s/\\/\\\\/g;
  $value =~ s/"/\\"/g;
  return '"' . $value . '"';
}

sub _authoritative_auth_scope {
  return 'irc://overnet.irc.local/local';
}

sub _fixed_authoritative_auth_challenge {
  return 'interop-fixed-auth-challenge';
}

sub _build_authoritative_auth_event_hash {
  my (%args) = @_;
  return $args{key}->create_event_hash(
    kind       => 22242,
    created_at => ($args{created_at} || 1_744_301_000),
    content    => '',
    tags       => [
      [ 'relay', ($args{scope} || _authoritative_auth_scope()) ],
      [ 'challenge', ($args{challenge} || _fixed_authoritative_auth_challenge()) ],
    ],
  );
}

sub _build_authoritative_auth_payload {
  my (%args) = @_;
  return encode_base64(
    encode_json(
      _build_authoritative_auth_event_hash(%args)
    ),
    '',
  );
}

sub _authenticate_payload_chunks {
  my ($payload) = @_;
  my $remaining = defined($payload) ? $payload : '';
  my $payload_length = length($remaining);
  my @chunks;
  while (length($remaining) > 400) {
    push @chunks, substr($remaining, 0, 400, '');
  }
  if (length $remaining) {
    push @chunks, $remaining;
  }
  if (!$payload_length || ($payload_length % 400) == 0) {
    push @chunks, '+';
  }
  return @chunks;
}

sub _connect_irc_client {
  my ($port) = @_;

  my $socket = IO::Socket::INET->new(
    PeerHost => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => 3,
  ) or die "Can't connect fake IRC client to 127.0.0.1:$port: $!";

  binmode($socket, ':raw');
  $socket->autoflush(1);
  return {
    socket      => $socket,
    read_buffer => '',
  };
}

sub _connect_irc_client_tls {
  my ($port) = @_;

  my $socket = IO::Socket::SSL->new(
    PeerHost        => '127.0.0.1',
    PeerPort        => $port,
    SSL_verify_mode => SSL_VERIFY_NONE,
    Timeout         => 3,
  ) or die "Can't connect fake TLS IRC client to 127.0.0.1:$port: " . IO::Socket::SSL::errstr();

  binmode($socket, ':raw');
  $socket->autoflush(1);
  return {
    socket      => $socket,
    read_buffer => '',
  };
}

sub _write_client_line {
  my ($client, $line) = @_;

  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    die "Failed to write fake IRC client line: $!\n"
      unless defined $written;
    $offset += $written;
  }
}

sub _read_client_line {
  my ($client, $timeout_ms) = @_;
  my (undef, $caller_file, $caller_line) = caller;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    die "Timed out waiting for IRC client line at $caller_file line $caller_line\n"
      unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected before sending a line at $caller_file line $caller_line\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _read_client_line_optional {
  my ($client, $timeout_ms) = @_;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    return undef unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected unexpectedly\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _observer_join_channel {
  my ($client) = @_;
  _write_client_line($client, 'NICK observer');
  _write_client_line($client, 'USER observer 0 * :Observer');
  _write_client_line($client, 'JOIN #overnet');

  is _read_client_line($client, 3_000), ':overnet.irc.local 001 observer :Welcome to Overnet IRC',
    'observer receives 001';
  is _read_client_line($client, 3_000), ':overnet.irc.local 005 observer CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=local :are supported by this server',
    'observer receives 005';
  is _read_client_line($client, 3_000), ':overnet.irc.local 422 observer :MOTD File is missing',
    'observer receives 422';
  is _read_client_line($client, 3_000), ':observer JOIN #overnet',
    'observer receives its JOIN echo';
  like _read_client_line($client, 3_000), qr/\A:overnet\.irc\.local 353 observer = #overnet :observer\z/,
    'observer receives NAMES bootstrap';
  is _read_client_line($client, 3_000), ':overnet.irc.local 366 observer #overnet :End of /NAMES list.',
    'observer receives end-of-names';
}

sub _drain_client_text {
  my ($client, %args) = @_;
  my $max_wait_ms = $args{max_wait_ms} || 3_000;
  my $idle_ms = $args{idle_ms} || 250;
  my $deadline = time() + ($max_wait_ms / 1000);
  my $text = '';

  while (time() < $deadline) {
    my $line = _read_client_line_optional($client, $idle_ms);
    last unless defined $line;
    $text .= $line . "\n";
  }

  return $text;
}

sub _read_client_text_until {
  my ($client, $pattern, $timeout_ms) = @_;
  my $deadline = time() + ($timeout_ms / 1000);
  my $text = '';

  while (time() < $deadline) {
    my $line = _read_client_line_optional($client, 250);
    next unless defined $line;
    $text .= $line . "\n";
    last if $line =~ $pattern;
  }

  return $text;
}

sub _read_ready_json {
  my ($handle, $timeout_ms) = @_;
  my $selector = IO::Select->new($handle);
  my @ready = $selector->can_read($timeout_ms / 1000);
  return undef unless @ready;
  my $line = <$handle>;
  return undef unless defined $line;
  chomp $line;
  return decode_json($line);
}

sub _slurp_handle {
  my ($handle) = @_;
  return '' unless defined $handle;
  my $content = '';
  while (1) {
    my $bytes = sysread($handle, my $chunk, 4096);
    last unless defined $bytes && $bytes > 0;
    $content .= $chunk;
  }
  return $content;
}

sub _spawn_live_irc_server {
  my (%args) = @_;
  my $listen_port = $args{listen_port};
  my $tls = $args{tls};
  my $adapter_config = $args{adapter_config} || {};
  my $fixed_auth_challenge = $args{fixed_auth_challenge};
  my $seed_channel = $args{seed_channel};
  my $tmpdir = tempdir(CLEANUP => 1);
  my $script_path = File::Spec->catfile($tmpdir, 'live-irc-server.pl');
  my $signing_key_file = File::Spec->catfile($tmpdir, 'signing-key.pem');

  open my $fh, '>', $script_path
    or die "Unable to write $script_path: $!";
  print {$fh} <<'PERL';
use strict;
use warnings;
use JSON::PP qw(encode_json);
use File::Path qw(make_path);
use File::Spec;
use Net::Nostr::Group ();
use lib $ENV{OVERNET_PROGRAM_LIB};
use lib $ENV{OVERNET_CODE_LIB};
use lib $ENV{OVERNET_CODE_LOCAL_LIB};
use Overnet::Core::Nostr;
use Overnet::Authority::HostedChannel;
use Overnet::Program::Host;
use Overnet::Program::Runtime;

my $state_dir = $ENV{OVERNET_LIVE_STATE_DIR};
make_path($state_dir) unless -d $state_dir;
my $signing_key_file = File::Spec->catfile($state_dir, 'signing-key.pem');
if (!-f $signing_key_file) {
  Overnet::Core::Nostr->generate_key->save_privkey($signing_key_file);
}

my %config = (
  adapter_id       => 'irc.live',
  network          => 'local',
  listen_host      => '127.0.0.1',
  listen_port      => 0 + $ENV{OVERNET_LIVE_PORT},
  server_name      => 'overnet.irc.local',
  signing_key_file => $signing_key_file,
  adapter_config   => (
    defined($ENV{OVERNET_ADAPTER_CONFIG_JSON}) && length($ENV{OVERNET_ADAPTER_CONFIG_JSON})
      ? (JSON::PP::decode_json($ENV{OVERNET_ADAPTER_CONFIG_JSON}))
      : {}
  ),
);
if (defined($ENV{OVERNET_TLS_CERT}) && length($ENV{OVERNET_TLS_CERT})) {
  $config{tls} = {
    enabled          => 1,
    mode             => 'server',
    cert_chain_file  => $ENV{OVERNET_TLS_CERT},
    private_key_file => $ENV{OVERNET_TLS_KEY},
    min_version      => 'TLSv1.2',
  };
}

my $runtime = Overnet::Program::Runtime->new(config => \%config);
if (defined($ENV{OVERNET_SEED_CHANNEL}) && length($ENV{OVERNET_SEED_CHANNEL})) {
  my $group_host = $config{adapter_config}{group_host} || '';
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => $config{network},
    channel => $ENV{OVERNET_SEED_CHANNEL},
  );
  if (length($group_host) && defined($group_id) && length($group_id)) {
    my $stream = join(':', 'irc.authority.nip29', $config{network}, $group_host, $group_id);
    my $seed_key = Overnet::Core::Nostr->generate_key;
    my $event = Net::Nostr::Group->metadata(
      pubkey     => $seed_key->pubkey_hex,
      group_id   => $group_id,
      created_at => 1_744_301_000,
    )->to_hash;
    push @{$event->{tags}}, [ 'name', $ENV{OVERNET_SEED_CHANNEL} ];
    $runtime->append_event(
      stream => $stream,
      event  => $event,
    );
  }
}
$runtime->register_adapter_definition(
  adapter_id => 'irc.live',
  definition => {
    kind             => 'class',
    class            => 'Overnet::Adapter::IRC',
    lib_dirs         => [ $ENV{OVERNET_IRC_LIB} ],
    constructor_args => {},
  },
) or die "register adapter failed\n";

my $host = Overnet::Program::Host->new(
  command     => [ $^X, $ENV{OVERNET_PROGRAM_PATH} ],
  runtime     => $runtime,
  program_id  => 'overnet.program.irc_server',
  permissions => [
    'adapters.use',
    'subscriptions.read',
    'adapters.derive',
    'events.append',
    'events.read',
    'overnet.emit_event',
    'overnet.emit_state',
    'overnet.emit_private_message',
    'overnet.emit_capabilities',
  ],
  services => {
    'adapters.open_session'        => {},
    'adapters.map_input'           => {},
    'adapters.derive'             => {},
    'adapters.close_session'       => {},
    'events.append'               => {},
    'events.read'                 => {},
    'subscriptions.open'           => {},
    'subscriptions.close'          => {},
    'overnet.emit_event'           => {},
    'overnet.emit_state'           => {},
    'overnet.emit_private_message' => {},
    'overnet.emit_capabilities'    => {},
  },
  startup_timeout_ms  => 10_000,
  shutdown_timeout_ms => 5_000,
);

$host->_spawn_child;
my $ready;
while (1) {
  $host->pump(timeout_ms => 100);
  for my $notification (@{$host->observed_notifications || []}) {
    next unless ($notification->{method} || '') eq 'program.health';
    next unless ($notification->{params}{status} || '') eq 'ready';
    next unless ref($notification->{params}{details}) eq 'HASH';
    $ready = $notification->{params}{details};
    last;
  }
  last if $ready;
  die "server exited unexpectedly during startup\n" if $host->has_exited;
}

print encode_json($ready), "\n";
$| = 1;

local $SIG{TERM} = sub {
  eval { $host->request_shutdown(reason => 'term') };
  exit 0;
};
local $SIG{INT} = sub {
  eval { $host->request_shutdown(reason => 'int') };
  exit 0;
};

while (1) {
  $host->pump(timeout_ms => 100);
  die "server exited unexpectedly after startup\n" if $host->has_exited;
}
PERL
  close $fh;

  my %env = (
    %ENV,
    OVERNET_PROGRAM_LIB      => File::Spec->catdir($program_repo, 'lib'),
    OVERNET_CODE_LIB         => $code_lib,
    OVERNET_CODE_LOCAL_LIB   => $code_local_lib,
    OVERNET_IRC_LIB          => $irc_lib,
    OVERNET_PROGRAM_PATH     => $program_path,
    OVERNET_LIVE_PORT        => $listen_port,
    OVERNET_LIVE_STATE_DIR   => $tmpdir,
    OVERNET_ADAPTER_CONFIG_JSON => encode_json($adapter_config),
    OVERNET_SEED_CHANNEL     => (defined($seed_channel) ? $seed_channel : ''),
    OVERNET_TLS_CERT         => ($tls ? $tls->{cert_chain_file} : ''),
    OVERNET_TLS_KEY          => ($tls ? $tls->{private_key_file} : ''),
  );
  if (defined($fixed_auth_challenge) && length($fixed_auth_challenge)) {
    my $perl5opt = $ENV{PERL5OPT} || '';
    $perl5opt .= ' ' if length $perl5opt;
    $perl5opt .= join ' ',
      '-I' . File::Spec->catdir($program_repo, 'lib'),
      '-I' . $code_lib,
      '-I' . $code_local_lib,
      '-I' . $irc_lib,
      '-MOvernet::Test::ClientInteropHooks';
    $env{PERL5OPT} = $perl5opt;
    $env{OVERNET_FIXED_AUTH_CHALLENGE} = $fixed_auth_challenge;
  }

  my $stderr = gensym();
  local %ENV = %env;
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    $^X,
    $script_path,
  );
  close $stdin;

  my $ready = _read_ready_json($stdout, 10_000);
  my $startup_error = '';
  $startup_error = _slurp_handle($stderr)
    unless $ready;
  return {
    pid          => $pid,
    stdout       => $stdout,
    stderr       => $stderr,
    tmpdir       => $tmpdir,
    script_path  => $script_path,
    startup_error => $startup_error,
    ready_details => $ready,
  };
}

sub _stop_spawned_process {
  my ($proc) = @_;
  return unless $proc && $proc->{pid};

  _stop_spawned_process($proc->{wm}) if $proc->{wm};

  kill 'TERM', $proc->{pid};
  my $deadline = time() + 5;
  while (time() < $deadline) {
    my $reaped = waitpid($proc->{pid}, WNOHANG);
    last if $reaped == $proc->{pid};
    sleep 0.05;
  }

  if (waitpid($proc->{pid}, WNOHANG) == 0) {
    kill 'KILL', $proc->{pid};
    waitpid($proc->{pid}, 0);
  }
}

sub _spawn_xvfb {
  my ($display) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'Xvfb',
    $display,
    '-screen', '0', '1024x768x24',
  );
  close $stdin;
  sleep 1;
  my $wm;
  for my $candidate (
    [ 'fluxbox' ],
    [ 'xfwm4', '--compositor=off' ],
    [ 'twm' ],
  ) {
    next unless -x "/usr/bin/$candidate->[0]";
    my $wm_stderr = gensym();
    local %ENV = (
      %ENV,
      DISPLAY => $display,
    );
    my $wm_pid = open3(
      my $wm_stdin,
      my $wm_stdout,
      $wm_stderr,
      @$candidate,
    );
    close $wm_stdin;
    $wm = {
      pid    => $wm_pid,
      stdout => $wm_stdout,
      stderr => $wm_stderr,
    };
    sleep 0.5;
    last;
  }
  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
    wm     => $wm,
  };
}

sub _generate_tls_material {
  my ($dir) = @_;
  my $cert_path = File::Spec->catfile($dir, 'irc-server-cert.pem');
  my $key_path = File::Spec->catfile($dir, 'irc-server-key.pem');

  my ($cert, $key) = CERT_create(
    subject => { commonName => '127.0.0.1' },
    subjectAltNames => [
      [ IP  => '127.0.0.1' ],
      [ DNS => 'localhost' ],
    ],
  );
  PEM_cert2file($cert, $cert_path);
  PEM_key2file($key, $key_path);

  return {
    cert_chain_file => $cert_path,
    private_key_file => $key_path,
  };
}

sub _spawn_authoritative_interop_server {
  my (%args) = @_;
  my $port = $args{listen_port} || _free_port();
  return _spawn_live_irc_server(
    listen_port         => $port,
    fixed_auth_challenge => _fixed_authoritative_auth_challenge(),
    seed_channel        => '#overnet',
    adapter_config      => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
    },
  );
}

sub _authenticate_observer_authoritative {
  my ($server) = @_;
  my $port = $server->{ready_details}{listen_port};
  my $client = _connect_irc_client($port);
  my $auth_key = Overnet::Core::Nostr->generate_key;

  _write_client_line($client, 'CAP LS 302');
  _write_client_line($client, 'CAP REQ :message-tags server-time account-tag account-notify');
  _write_client_line($client, 'NICK observer');
  _write_client_line($client, 'USER observer 0 * :Observer');
  _write_client_line($client, 'CAP END');

  like _read_client_line($client, 3_000), qr/\A:overnet\.irc\.local CAP \* LS :/,
    'authoritative observer receives CAP LS';
  is _read_client_line($client, 3_000), ':overnet.irc.local CAP * ACK :message-tags server-time account-tag account-notify',
    'authoritative observer receives CAP ACK';
  like _read_client_line($client, 3_000), qr/\A(?:\@time=\S+ )?:overnet\.irc\.local 001 observer :Welcome to Overnet IRC\z/,
    'authoritative observer receives 001';
  like _read_client_line($client, 3_000), qr/\A(?:\@time=\S+ )?:overnet\.irc\.local 005 observer /,
    'authoritative observer receives 005';
  like _read_client_line($client, 3_000), qr/\A(?:\@time=\S+ )?:overnet\.irc\.local 422 observer :MOTD File is missing\z/,
    'authoritative observer receives 422';

  _write_client_line($client, 'OVERNETAUTH CHALLENGE');
  like _read_client_line($client, 3_000), qr/\A(?:\@time=\S+ )?:overnet\.irc\.local NOTICE observer :OVERNETAUTH CHALLENGE \Q@{[_fixed_authoritative_auth_challenge()]}\E\z/,
    'authoritative observer receives fixed auth challenge';

  _write_client_line(
    $client,
    'OVERNETAUTH AUTH ' . _build_authoritative_auth_payload(
      key       => $auth_key,
      challenge => _fixed_authoritative_auth_challenge(),
      scope     => _authoritative_auth_scope(),
    ),
  );
  my $auth_text = _read_client_text_until($client, qr/OVERNETAUTH AUTH [0-9a-f]{64}\z/, 3_000);
  like $auth_text, qr/(?:\A|\n)(?:\@time=\S+ )?(?:\@account=[0-9a-f]{64} )?:observer![^ ]+ ACCOUNT [0-9a-f]{64}(?:\n|\z)/,
    'authoritative observer sees account identity state during auth';
  like $auth_text, qr/(?:\@time=\S+ )?:overnet\.irc\.local NOTICE observer :OVERNETAUTH AUTH [0-9a-f]{64}/,
    'authoritative observer authenticates';

  return $client;
}

sub _run_irssi_smoke {
  my (%args) = @_;
  my $home = tempdir(CLEANUP => 1);
  my $script = File::Spec->catfile($home, 'irssi-smoke.expect');
  open my $fh, '>', $script
    or die "Unable to write $script: $!";
  print {$fh} <<'EXPECT';
#!/usr/bin/expect -f
set timeout 20
log_user 1
set home [lindex $argv 0]
set port [lindex $argv 1]
spawn env TERM=xterm irssi --home $home --connect 127.0.0.1 --port $port --nick irssi_smoke
after 4000
send -- "/join #overnet\r"
after 2500
send -- "/msg #overnet hi-from-irssi\r"
after 2500
send -- "/quit\r"
expect eof
EXPECT
  close $fh;
  chmod 0755, $script
    or die "Unable to chmod $script: $!";

  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'expect',
    $script,
    $home,
    $args{port},
  );
  close $stdin;

  waitpid($pid, 0);
  return {
    exit_code => $? >> 8,
    output    => _slurp_handle($stdout),
    error     => _slurp_handle($stderr),
  };
}

sub _run_irssi_authoritative_smoke {
  my (%args) = @_;
  my $home = tempdir(CLEANUP => 1);
  my $script = File::Spec->catfile($home, 'irssi-authoritative-smoke.expect');
  my $auth_key = Overnet::Core::Nostr->generate_key;
  my $updated_key = Overnet::Core::Nostr->generate_key;
  my @payload1 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key       => $auth_key,
      challenge => _fixed_authoritative_auth_challenge(),
      scope     => _authoritative_auth_scope(),
    )
  );
  my @payload2 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key        => $updated_key,
      challenge  => _fixed_authoritative_auth_challenge(),
      scope      => _authoritative_auth_scope(),
      created_at => 1_744_301_001,
    )
  );

  open my $fh, '>', $script
    or die "Unable to write $script: $!";
  print {$fh} <<'EXPECT';
#!/usr/bin/expect -f
set timeout 30
log_user 1
set home [lindex $argv 0]
set port [lindex $argv 1]
spawn env TERM=xterm irssi --home $home --connect 127.0.0.1 --port $port --nick irssi_auth
after 3000
EXPECT
  for my $line (
    '/quote CAP LS 302',
    '/quote CAP REQ :sasl account-tag account-notify server-time',
    '/quote AUTHENTICATE NOSTR',
  ) {
    print {$fh} 'send -- ' . _tcl_quote($line . "\r") . "\n";
    print {$fh} "after 1200\n";
  }
  for my $chunk (@payload1) {
    print {$fh} 'send -- ' . _tcl_quote('/quote AUTHENTICATE ' . $chunk . "\r") . "\n";
    print {$fh} "after 800\n";
  }
  for my $line (
    '/quote CAP END',
  ) {
    print {$fh} 'send -- ' . _tcl_quote($line . "\r") . "\n";
    print {$fh} "after 1500\n";
  }
  print {$fh} 'send -- ' . _tcl_quote('/msg observer hi-from-irssi-auth1' . "\r") . "\n";
  print {$fh} "after 1500\n";
  for my $line (
    '/quote AUTHENTICATE NOSTR',
  ) {
    print {$fh} 'send -- ' . _tcl_quote($line . "\r") . "\n";
    print {$fh} "after 1200\n";
  }
  for my $chunk (@payload2) {
    print {$fh} 'send -- ' . _tcl_quote('/quote AUTHENTICATE ' . $chunk . "\r") . "\n";
    print {$fh} "after 800\n";
  }
  print {$fh} 'send -- ' . _tcl_quote('/msg observer hi-from-irssi-auth2' . "\r") . "\n";
  print {$fh} "after 2500\n";
  print {$fh} 'send -- ' . _tcl_quote('/quit' . "\r") . "\n";
  print {$fh} "expect eof\n";
  close $fh;
  chmod 0755, $script
    or die "Unable to chmod $script: $!";

  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'expect',
    $script,
    $home,
    $args{port},
  );
  close $stdin;

  waitpid($pid, 0);
  return {
    exit_code => $? >> 8,
    output    => _slurp_handle($stdout),
    error     => _slurp_handle($stderr),
  };
}

sub _spawn_weechat_smoke {
  my (%args) = @_;
  my $home = tempdir(CLEANUP => 1);
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'timeout',
    '20',
    'weechat-headless',
    '--stdout',
    '-d', $home,
    sprintf('irc://weechat_smoke@127.0.0.1:%d/#overnet', $args{port}),
  );
  close $stdin;

  my $fifo;
  my $deadline = time() + 10;
  while (time() < $deadline) {
    ($fifo) = grep { -p $_ } glob(File::Spec->catfile($home, 'weechat_fifo_*'));
    last if $fifo;
    sleep 0.1;
  }

  return {
    fifo   => $fifo,
    home   => $home,
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _spawn_weechat_authoritative_smoke {
  my (%args) = @_;
  my $home = tempdir(CLEANUP => 1);
  my $auth_key = Overnet::Core::Nostr->generate_key;
  my $updated_key = Overnet::Core::Nostr->generate_key;
  my @payload1 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key       => $auth_key,
      challenge => _fixed_authoritative_auth_challenge(),
      scope     => _authoritative_auth_scope(),
    )
  );
  my @payload2 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key        => $updated_key,
      challenge  => _fixed_authoritative_auth_challenge(),
      scope      => _authoritative_auth_scope(),
      created_at => 1_744_301_001,
    )
  );

  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'timeout',
    '40',
    'weechat-headless',
    '--stdout',
    '-d', $home,
    sprintf('irc://weechat_auth@127.0.0.1:%d', $args{port}),
  );
  close $stdin;

  my $fifo;
  my $deadline = time() + 10;
  while (time() < $deadline) {
    ($fifo) = grep { -p $_ } glob(File::Spec->catfile($home, 'weechat_fifo_*'));
    last if $fifo;
    sleep 0.1;
  }

  my $proc = {
    fifo   => $fifo,
    home   => $home,
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
  return $proc unless $fifo;

  my @quote_prefixes = (
    '*/quote ',
    'irc.127.0.0.1.server */quote ',
    'irc.server.127.0.0.1 */quote ',
  );
  sleep 2.0;
  for my $prefix (@quote_prefixes) {
    _write_weechat_command($proc, $prefix . 'CAP LS 302');
  }
  sleep 1.0;
  for my $prefix (@quote_prefixes) {
    _write_weechat_command($proc, $prefix . 'CAP REQ :sasl account-tag account-notify server-time');
  }
  sleep 1.0;
  for my $prefix (@quote_prefixes) {
    _write_weechat_command($proc, $prefix . 'AUTHENTICATE NOSTR');
  }
  sleep 1.5;
  for my $chunk (@payload1) {
    for my $prefix (@quote_prefixes) {
      _write_weechat_command($proc, $prefix . 'AUTHENTICATE ' . $chunk);
    }
    sleep 0.8;
  }
  sleep 1.0;
  for my $prefix (@quote_prefixes) {
    _write_weechat_command($proc, $prefix . 'CAP END');
  }
  sleep 1.0;
  for my $command (
    '*/msg observer hi-from-weechat-auth1',
    '*/quote PRIVMSG observer :hi-from-weechat-auth1',
    'irc.127.0.0.1.server */msg observer hi-from-weechat-auth1',
    'irc.127.0.0.1.server */quote PRIVMSG observer :hi-from-weechat-auth1',
  ) {
    _write_weechat_command($proc, $command);
  }
  sleep 1.0;
  for my $prefix (@quote_prefixes) {
    _write_weechat_command($proc, $prefix . 'AUTHENTICATE NOSTR');
  }
  sleep 1.5;
  for my $chunk (@payload2) {
    for my $prefix (@quote_prefixes) {
      _write_weechat_command($proc, $prefix . 'AUTHENTICATE ' . $chunk);
    }
    sleep 0.8;
  }
  sleep 1.0;
  for my $command (
    '*/msg observer hi-from-weechat-auth2',
    '*/quote PRIVMSG observer :hi-from-weechat-auth2',
    'irc.127.0.0.1.server */msg observer hi-from-weechat-auth2',
    'irc.127.0.0.1.server */quote PRIVMSG observer :hi-from-weechat-auth2',
  ) {
    _write_weechat_command($proc, $command);
  }
  sleep 2.0;

  return $proc;
}

sub _write_weechat_command {
  my ($proc, $command) = @_;
  open my $fh, '>', $proc->{fifo}
    or die "Unable to open WeeChat fifo $proc->{fifo}: $!";
  print {$fh} $command . "\n";
  close $fh;
}

sub _stop_weechat_smoke {
  my ($proc) = @_;
  _write_weechat_command($proc, '*/quit');
  waitpid($proc->{pid}, 0);
  return {
    exit_code => $? >> 8,
    output    => _slurp_handle($proc->{stdout}),
    error     => _slurp_handle($proc->{stderr}),
  };
}

sub _hexchat_existing_command {
  my (%args) = @_;
  local %ENV = (
    %ENV,
    DISPLAY => $args{display},
  );
  return system(
    'timeout',
    $args{timeout_seconds} || '5',
    'hexchat',
    '--existing',
    '--command=' . $args{command},
  );
}

sub _spawn_hexchat_smoke {
  my (%args) = @_;
  my $cfgdir = tempdir(CLEANUP => 1);
  my $addons_dir = File::Spec->catdir($cfgdir, 'addons');
  mkdir $addons_dir
    or die "Unable to create $addons_dir: $!"
    unless -d $addons_dir;
  my $addon_path = File::Spec->catfile($addons_dir, 'overnet_smoke.py');
  open my $addon_fh, '>', $addon_path
    or die "Unable to write $addon_path: $!";
  print {$addon_fh} <<'PYTHON';
__module_name__ = 'overnet_smoke'
__module_version__ = '1.0'
__module_description__ = 'Overnet HexChat smoke automation'

import hexchat

_sent = False

def _send_message(userdata):
    hexchat.command('say hi-from-hexchat')
    return 0

def _on_you_join(word, word_eol, userdata):
    global _sent
    channel = hexchat.get_info('channel') or ''
    if _sent or channel != '#overnet':
        return hexchat.EAT_NONE
    _sent = True
    hexchat.hook_timer(1000, _send_message)
    return hexchat.EAT_NONE

hexchat.hook_print('You Join', _on_you_join)
PYTHON
  close $addon_fh;

  my $stderr = gensym();
  my $display = ':' . (90 + int(rand(100)));
  my $xvfb = _spawn_xvfb($display);

  local %ENV = (
    %ENV,
    DISPLAY       => $display,
    SSL_CERT_FILE => $args{cert_chain_file},
  );

  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'hexchat',
    '--cfgdir', $cfgdir,
    sprintf('ircs://127.0.0.1:%d/#overnet', $args{port}),
  );
  close $stdin;

  my $existing_ok = 0;
  my $ready_deadline = time() + 15;
  while (time() < $ready_deadline) {
    my $rc = _hexchat_existing_command(
      display         => $display,
      timeout_seconds => 2,
      command         => 'echo hexchat-ready',
    );
    if (($rc >> 8) == 0) {
      $existing_ok = 1;
      last;
    }
    sleep 0.5;
  }

  return {
    existing_ok => $existing_ok,
    display     => $display,
    pid         => $pid,
    stdout      => $stdout,
    stderr      => $stderr,
    xvfb        => $xvfb,
  };
}

sub _spawn_hexchat_authoritative_smoke {
  my (%args) = @_;
  my $cfgdir = tempdir(CLEANUP => 1);
  my $addons_dir = File::Spec->catdir($cfgdir, 'addons');
  mkdir $addons_dir
    or die "Unable to create $addons_dir: $!"
    unless -d $addons_dir;

  my $auth_key = Overnet::Core::Nostr->generate_key;
  my $updated_key = Overnet::Core::Nostr->generate_key;
  my @payload1 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key       => $auth_key,
      challenge => _fixed_authoritative_auth_challenge(),
      scope     => _authoritative_auth_scope(),
    )
  );
  my @payload2 = _authenticate_payload_chunks(
    _build_authoritative_auth_payload(
      key        => $updated_key,
      challenge  => _fixed_authoritative_auth_challenge(),
      scope      => _authoritative_auth_scope(),
      created_at => 1_744_301_001,
    )
  );

  my $addon_path = File::Spec->catfile($addons_dir, 'overnet_authoritative_smoke.py');
  open my $addon_fh, '>', $addon_path
    or die "Unable to write $addon_path: $!";
  print {$addon_fh} <<'PYTHON';
__module_name__ = 'overnet_authoritative_smoke'
__module_version__ = '1.0'
__module_description__ = 'Overnet HexChat authoritative smoke automation'

import hexchat

_commands = [
PYTHON
  for my $command (
    'quote CAP LS 302',
    'quote CAP REQ :sasl account-tag account-notify server-time',
    'quote AUTHENTICATE NOSTR',
    (map { 'quote AUTHENTICATE ' . $_ } @payload1),
    'quote CAP END',
    'quote PRIVMSG observer :hi-from-hexchat-auth1',
    'quote AUTHENTICATE NOSTR',
    (map { 'quote AUTHENTICATE ' . $_ } @payload2),
    'quote PRIVMSG observer :hi-from-hexchat-auth2',
  ) {
    print {$addon_fh} '    ' . _shell_quote($command) . ",\n";
  }
  print {$addon_fh} <<'PYTHON';
]
_index = 0

def _run_next(userdata):
    global _index
    if _index >= len(_commands):
        return 0
    hexchat.command(_commands[_index])
    _index += 1
    return 1 if _index < len(_commands) else 0

def _start_sequence(word, word_eol, userdata):
    hexchat.hook_timer(1000, _run_next)
    return hexchat.EAT_NONE

hexchat.hook_print('Connected', _start_sequence)
PYTHON
  close $addon_fh;

  my $stderr = gensym();
  my $display = ':' . (190 + int(rand(100)));
  my $xvfb = _spawn_xvfb($display);

  local %ENV = (
    %ENV,
    DISPLAY => $display,
  );

  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    'hexchat',
    '--cfgdir', $cfgdir,
    sprintf('irc://127.0.0.1:%d', $args{port}),
  );
  close $stdin;

  my $existing_ok = 0;
  my $ready_deadline = time() + 15;
  while (time() < $ready_deadline) {
    my $rc = _hexchat_existing_command(
      display         => $display,
      timeout_seconds => 2,
      command         => 'echo hexchat-ready',
    );
    if (($rc >> 8) == 0) {
      $existing_ok = 1;
      last;
    }
    sleep 0.5;
  }

  return {
    existing_ok => $existing_ok,
    display     => $display,
    pid         => $pid,
    stdout      => $stdout,
    stderr      => $stderr,
    xvfb        => $xvfb,
  };
}

sub _stop_hexchat_smoke {
  my ($proc) = @_;

  my $quit_rc = _hexchat_existing_command(
    display         => $proc->{display},
    timeout_seconds => 5,
    command         => '/quit',
  );

  my $child_status;
  my $wait_deadline = time() + 15;
  while (time() < $wait_deadline) {
    my $reaped = waitpid($proc->{pid}, WNOHANG);
    if ($reaped == $proc->{pid}) {
      $child_status = $?;
      last;
    }
    sleep 0.1;
  }
  if (waitpid($proc->{pid}, WNOHANG) == 0) {
    kill 'TERM', $proc->{pid};
    waitpid($proc->{pid}, 0);
    $child_status = $?;
  }

  _stop_spawned_process($proc->{xvfb});

  return {
    exit_code => defined($child_status) ? ($child_status >> 8) : undef,
    quit_rc   => $quit_rc >> 8,
  };
}

SKIP: {
  skip 'irssi or expect not installed', 11
    unless -x '/usr/bin/irssi' && -x '/usr/bin/expect';

  my $port = _free_port();
  my $server = _spawn_live_irc_server(listen_port => $port);
  ok $server->{ready_details}, 'live plain IRC server publishes ready details for irssi smoke coverage';
  my $observer = _connect_irc_client($server->{ready_details}{listen_port});
  _observer_join_channel($observer);

  my $result = _run_irssi_smoke(port => $server->{ready_details}{listen_port});
  is $result->{exit_code}, 0, 'irssi smoke run exits cleanly';

  my $observer_text = _drain_client_text($observer);
  like $observer_text, qr/:irssi_smoke JOIN #overnet/,
    'observer sees irssi join the channel';
  like $observer_text, qr/:irssi_smoke PRIVMSG #overnet :hi-from-irssi/,
    'observer sees irssi send a channel message';

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'plain live IRC server stops cleanly after irssi smoke coverage';

  close $observer->{socket};
}

SKIP: {
  skip 'WeeChat not installed', 11
    unless -x '/usr/bin/weechat-headless';

  my $port = _free_port();
  my $server = _spawn_live_irc_server(listen_port => $port);
  ok $server->{ready_details}, 'live plain IRC server publishes ready details for WeeChat smoke coverage';
  my $observer = _connect_irc_client($server->{ready_details}{listen_port});
  _observer_join_channel($observer);

  my $result = _spawn_weechat_smoke(port => $server->{ready_details}{listen_port});
  ok $result->{fifo}, 'WeeChat exposes a fifo control pipe';

  my $observer_text = _read_client_text_until($observer, qr/:weechat_smoke JOIN #overnet/, 8_000);
  like $observer_text, qr/:weechat_smoke JOIN #overnet/,
    'observer sees WeeChat join the channel';

  my $message_text = '';
  for my $command (
    '*hi-from-weechat',
    '*/msg #overnet hi-from-weechat',
    '*/quote PRIVMSG #overnet :hi-from-weechat',
    'irc.127.0.0.1.#overnet *hi-from-weechat',
    'irc.127.0.0.1.#overnet */msg #overnet hi-from-weechat',
    'irc.127.0.0.1.#overnet */quote PRIVMSG #overnet :hi-from-weechat',
  ) {
    _write_weechat_command($result, $command);
    $message_text = _read_client_text_until($observer, qr/:weechat_smoke PRIVMSG #overnet :hi-from-weechat/, 1_500);
    last if $message_text =~ /:weechat_smoke PRIVMSG #overnet :hi-from-weechat/;
  }
  like $message_text, qr/:weechat_smoke PRIVMSG #overnet :hi-from-weechat/,
    'observer sees WeeChat send a channel message';

  my $stop = _stop_weechat_smoke($result);
  is $stop->{exit_code}, 0, 'WeeChat smoke run exits cleanly';

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'plain live IRC server stops cleanly after WeeChat smoke coverage';

  close $observer->{socket};
}

SKIP: {
  skip 'HexChat or Xvfb not installed', 14
    unless -x '/usr/bin/hexchat' && -x '/usr/bin/Xvfb';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $tls = _generate_tls_material($tmpdir);
  my $port = _free_port();
  my $server = _spawn_live_irc_server(
    listen_port => $port,
    tls         => $tls,
  );
  ok $server->{ready_details}, 'live TLS IRC server publishes ready details for HexChat smoke coverage';
  my $observer = _connect_irc_client_tls($server->{ready_details}{listen_port});
  _observer_join_channel($observer);

  my $result = _spawn_hexchat_smoke(
    port            => $server->{ready_details}{listen_port},
    cert_chain_file => $tls->{cert_chain_file},
  );
  ok $result->{existing_ok}, 'HexChat exposes an existing instance for automation';

  my $observer_text = _read_client_text_until($observer, qr/:([^ ]+) JOIN #overnet/, 10_000);
  like $observer_text, qr/:([^ ]+) JOIN #overnet/,
    'observer sees HexChat join the channel';
  my ($hex_nick) = $observer_text =~ /:([^ ]+) JOIN #overnet/;
  ok defined $hex_nick && length $hex_nick, 'HexChat exposes a joined nick';

  my $message_text = _read_client_text_until($observer, qr/:\Q$hex_nick\E PRIVMSG #overnet :hi-from-hexchat/, 5_000);
  like $message_text, qr/:\Q$hex_nick\E PRIVMSG #overnet :hi-from-hexchat/,
    'observer sees HexChat send a channel message';

  my $stop = _stop_hexchat_smoke($result);
  is $stop->{quit_rc}, 0, 'HexChat accepts the quit command';
  is $stop->{exit_code}, 0, 'HexChat smoke run exits cleanly';

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'TLS live IRC server stops cleanly after HexChat smoke coverage';

  close $observer->{socket};
}

SKIP: {
  skip 'irssi or expect not installed', 7
    unless -x '/usr/bin/irssi' && -x '/usr/bin/expect';

  my $server = _spawn_authoritative_interop_server();
  ok $server->{ready_details}, 'authoritative live IRC server publishes ready details for irssi capability coverage';
  diag $server->{startup_error}
    unless $server->{ready_details};
  my $observer = _authenticate_observer_authoritative($server);

  my $result = _run_irssi_authoritative_smoke(port => $server->{ready_details}{listen_port});
  is $result->{exit_code}, 0, 'irssi authoritative smoke run exits cleanly';
  diag($result->{output} . $result->{error})
    if $result->{exit_code};

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'authoritative live IRC server stops cleanly after irssi capability coverage';

  close $observer->{socket};
}

SKIP: {
  skip 'WeeChat not installed', 7
    unless -x '/usr/bin/weechat-headless';

  my $server = _spawn_authoritative_interop_server();
  ok $server->{ready_details}, 'authoritative live IRC server publishes ready details for WeeChat capability coverage';
  diag $server->{startup_error}
    unless $server->{ready_details};
  my $observer = _authenticate_observer_authoritative($server);

  my $result = _spawn_weechat_authoritative_smoke(port => $server->{ready_details}{listen_port});
  ok $result->{fifo}, 'WeeChat authoritative smoke exposes a fifo control pipe';
  my $stop = _stop_weechat_smoke($result);
  is $stop->{exit_code}, 0, 'WeeChat authoritative smoke run exits cleanly';
  diag($stop->{output} . $stop->{error})
    if $stop->{exit_code};

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'authoritative live IRC server stops cleanly after WeeChat capability coverage';

  close $observer->{socket};
}

SKIP: {
  skip 'HexChat or Xvfb not installed', 8
    unless -x '/usr/bin/hexchat' && -x '/usr/bin/Xvfb';

  my $server = _spawn_authoritative_interop_server();
  ok $server->{ready_details}, 'authoritative live IRC server publishes ready details for HexChat capability coverage';
  diag $server->{startup_error}
    unless $server->{ready_details};
  my $observer = _authenticate_observer_authoritative($server);

  my $result = _spawn_hexchat_authoritative_smoke(port => $server->{ready_details}{listen_port});
  ok $result->{existing_ok}, 'HexChat authoritative smoke exposes an existing instance for automation';

  my $stop = _stop_hexchat_smoke($result);
  is $stop->{exit_code}, 0, 'HexChat authoritative smoke run exits cleanly';
  diag(($result->{output} || '') . ($result->{error} || '') . ($stop->{output} || '') . ($stop->{error} || ''))
    if $stop->{exit_code};

  my $shutdown_ok = eval {
    _stop_spawned_process($server);
    1;
  };
  ok $shutdown_ok, 'authoritative live IRC server stops cleanly after HexChat capability coverage';

  close $observer->{socket};
}

done_testing;
