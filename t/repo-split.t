use strictures 2;
use File::Spec;
use FindBin;
use Test::More;

my $root = File::Spec->catdir($FindBin::Bin, '..');

use_ok('Overnet::Relay');
use_ok('Overnet::Relay::Store::File');
use_ok('Overnet::Relay::Sync');
use_ok('Overnet::Authority::HostedChannel::Relay');

ok -e File::Spec->catfile($root, 'bin', 'overnet-relay.pl'),        'relay-perl ships the relay daemon';
ok -e File::Spec->catfile($root, 'bin', 'overnet-relay-sync.pl'),   'relay-perl ships the relay sync CLI';
ok -e File::Spec->catfile($root, 'bin', 'overnet-relay-backup.pl'), 'relay-perl ships the relay backup CLI';
ok -e File::Spec->catfile($root, 'bin', 'overnet-release-gate.pl'), 'relay-perl ships the relay-backed release gate';

done_testing;
