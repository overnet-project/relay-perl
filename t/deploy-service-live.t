use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Socket::INET;
use IPC::Open3 qw(open3);
use JSON::PP qw(decode_json);
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Test::More;
use Time::HiRes qw(sleep time);

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

sub _spawn_process {
  my (@command) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    @command,
  );
  close $stdin;
  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _stop_process {
  my ($proc) = @_;
  return unless $proc && $proc->{pid};

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

  close $proc->{stdout} if $proc->{stdout};
  close $proc->{stderr} if $proc->{stderr};
}

sub _wait_for_health {
  my ($path) = @_;
  my $deadline = time() + 10;

  while (time() < $deadline) {
    if (-f $path && -s $path) {
      open my $fh, '<', $path
        or die "Can't open $path: $!";
      local $/;
      my $raw = <$fh>;
      close $fh;
      my $decoded = eval { decode_json($raw) };
      return $decoded if ref($decoded) eq 'HASH' && ($decoded->{status} || '') eq 'ready';
    }
    sleep 0.05;
  }

  die "Timed out waiting for ready health at $path\n";
}

sub _wait_for_port_ready {
  my ($port) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $sock = IO::Socket::INET->new(
      PeerHost => '127.0.0.1',
      PeerPort => $port,
      Proto    => 'tcp',
      Timeout  => 1,
    );
    if ($sock) {
      close $sock;
      return 1;
    }
    sleep 0.05;
  }

  return 0;
}

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $project_root = File::Spec->catdir($code_root, '..');
my $irc_root = File::Spec->catdir($project_root, 'overnet-program-irc');

my $relay_service_script = File::Spec->catfile($code_root, 'bin', 'overnet-relay-service.pl');
my $irc_service_script = File::Spec->catfile($irc_root, 'bin', 'overnet-irc-service.pl');

subtest 'relay service wrapper writes health and logs' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $port = _free_port();
  my $health_file = File::Spec->catfile($dir, 'relay-health.json');
  my $log_file = File::Spec->catfile($dir, 'relay.log');
  my $store_file = File::Spec->catfile($dir, 'relay-store.json');

  my $proc = _spawn_process(
    $^X,
    $relay_service_script,
    '--host', '127.0.0.1',
    '--port', $port,
    '--store-file', $store_file,
    '--health-file', $health_file,
    '--log-file', $log_file,
  );

  eval {
    my $health = _wait_for_health($health_file);
    is $health->{listen_port}, $port, 'relay health reports the listening port';
    ok _wait_for_port_ready($port), 'relay port becomes reachable';
    ok -f $log_file, 'relay log file was created';
  };
  my $error = $@;
  _stop_process($proc);
  die $error if $error;
};

subtest 'IRC service wrapper writes health logs and TLS material' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $port = _free_port();
  my $health_file = File::Spec->catfile($dir, 'irc-health.json');
  my $log_file = File::Spec->catfile($dir, 'irc.log');
  my $signing_key_file = File::Spec->catfile($dir, 'signing-key.pem');
  my $tls_cert_chain_file = File::Spec->catfile($dir, 'tls-cert.pem');
  my $tls_private_key_file = File::Spec->catfile($dir, 'tls-key.pem');

  my $proc = _spawn_process(
    $^X,
    $irc_service_script,
    '--adapter-id', 'irc.deploy.test',
    '--network', 'deploynet',
    '--listen-host', '127.0.0.1',
    '--listen-port', $port,
    '--server-name', 'irc.deploy.test',
    '--signing-key-file', $signing_key_file,
    '--group-host', 'groups.deploy.test',
    '--tls',
    '--tls-cert-chain-file', $tls_cert_chain_file,
    '--tls-private-key-file', $tls_private_key_file,
    '--health-file', $health_file,
    '--log-file', $log_file,
  );

  eval {
    my $health = _wait_for_health($health_file);
    is $health->{details}{listen_port}, $port, 'IRC health reports the listening port';
    ok _wait_for_port_ready($port), 'IRC port becomes reachable';
    ok -f $log_file, 'IRC log file was created';
    ok -f $signing_key_file, 'IRC service created a signing key';
    ok -f $tls_cert_chain_file, 'IRC service created a TLS cert';
    ok -f $tls_private_key_file, 'IRC service created a TLS key';
  };
  my $error = $@;
  _stop_process($proc);
  die $error if $error;
};

done_testing;
