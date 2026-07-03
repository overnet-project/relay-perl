use strictures 2;
use Test2::V0;
use File::Spec;
use FindBin;

my $perl         = $^X;
my $program_repo = File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server');
my $command      = File::Spec->catfile($program_repo, 'bin', 'overnet-irc-server');
my $local_server_module =
  File::Spec->catfile($program_repo, 'lib', 'Overnet', 'Program', 'IRC', 'Script', 'LocalServer.pm');

ok(-f $command, "$command exists");
my $status = system($perl, '-c', $command);
is($status, 0, "$command compiles");

my $server_help = qx{$perl $command local-server --help};
like($server_help, qr/--tls\b/mx,                 'local server help advertises TLS support');
like($server_help, qr/--tls-cert-chain-file\b/mx, 'local server help advertises TLS certificate support');

open my $server_fh, '<', $local_server_module
  or die "Unable to read $local_server_module: $!";
my $server_source = do { local $/ = undef; <$server_fh> };
close $server_fh;
like($server_source, qr/SSL_CERT_FILE=/mx, 'local server prints a verified HexChat TLS example');
like(
  $server_source,
  qr/ircs:\/\/%s:%d\/\#overnet/mx,
  'local server prints the HexChat channel URI without percent-encoding the hash'
);
unlike($server_source, qr/%23overnet/mx, 'local server does not percent-encode the HexChat channel hash');

my $client_help = qx{$perl $command chat-client --help};
like($client_help, qr/--tls\b/mx,           'local client help advertises TLS support');
like($client_help, qr/--tls-no-verify\b/mx, 'local client help advertises local self-signed TLS support');

done_testing;
