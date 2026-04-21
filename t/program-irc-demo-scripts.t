use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

my $perl = '/opt/perl-5.42/bin/perl';
my $program_repo = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-program-irc');
my @scripts = (
  File::Spec->catfile($program_repo, 'bin', 'overnet-irc-local-server.pl'),
  File::Spec->catfile($program_repo, 'bin', 'overnet-irc-chat-client.pl'),
);

for my $script (@scripts) {
  ok(-f $script, "$script exists");
  my $status = system($perl, '-c', $script);
  is($status, 0, "$script compiles");
}

my $server_help = qx{$perl $scripts[0] --help};
like($server_help, qr/--tls\b/, 'local server help advertises TLS support');
like($server_help, qr/--tls-cert-chain-file\b/, 'local server help advertises TLS certificate support');

open my $server_fh, '<', $scripts[0]
  or die "Unable to read $scripts[0]: $!";
my $server_source = do { local $/; <$server_fh> };
close $server_fh;
like($server_source, qr/SSL_CERT_FILE=/, 'local server prints a verified HexChat TLS example');
like($server_source, qr/ircs:\/\/%s:%d\/#overnet/, 'local server prints the HexChat channel URI without percent-encoding the hash');
unlike($server_source, qr/%23overnet/, 'local server does not percent-encode the HexChat channel hash');

my $client_help = qx{$perl $scripts[1] --help};
like($client_help, qr/--tls\b/, 'local client help advertises TLS support');
like($client_help, qr/--tls-no-verify\b/, 'local client help advertises local self-signed TLS support');

done_testing;
