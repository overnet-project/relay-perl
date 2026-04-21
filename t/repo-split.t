use strict;
use warnings;
use Test::More;

use lib 'lib';
use lib 'local/lib/perl5';
use lib '../overnet-core-perl/lib';
use lib '../overnet-core-perl/local/lib/perl5';

use_ok('Overnet::Relay');
use_ok('Overnet::Relay::Store::File');
use_ok('Overnet::Relay::Sync');
use_ok('Overnet::Authority::HostedChannel::Relay');

ok -e 'bin/overnet-relay.pl',
  'relay-perl ships the relay daemon';
ok -e 'bin/overnet-relay-sync.pl',
  'relay-perl ships the relay sync CLI';
ok -e 'bin/overnet-relay-backup.pl',
  'relay-perl ships the relay backup CLI';
ok -e 'bin/overnet-release-gate.pl',
  'relay-perl ships the relay-backed release gate';

done_testing;
