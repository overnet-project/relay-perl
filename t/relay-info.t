use strictures 2;

use JSON ();
use Test2::V0;

use Overnet::Relay::Info;

my $JSON = JSON->new->utf8->canonical;

subtest 'constructor validates argument shapes' => sub {
  like dies { Overnet::Relay::Info->new(bogus => 1, extra => 2) },
    qr/unknown\ argument\(s\):\ bogus,\ extra/mx, 'unknown arguments are reported sorted';
  like dies { Overnet::Relay::Info->new('odd') },
    qr/constructor\ arguments\ must\ be\ a\ hash\ or\ hash\ reference/mx,
    'odd argument lists are rejected';
  ok(Overnet::Relay::Info->new({name => 'hashref'}), 'hashref arguments are accepted');
  ok(Overnet::Relay::Info->new(name => 'list'),      'list arguments are accepted');
};

subtest 'structured fields are copied and defaulted' => sub {
  my $limitation = {max_subscriptions => 4};
  my $fees       = {admission => [{amount => 1_000, unit => 'msats'}]};
  my $info       = Overnet::Relay::Info->new(
    name           => 'structured',
    supported_nips => [11, 1],
    limitation     => $limitation,
    fees           => $fees,
    overnet        => {core_version => '0.1.0'},
  );

  is $info->supported_nips, [11, 1], 'supported NIPs are preserved';
  is $info->limitation, $limitation, 'limitation content is preserved';
  ok $info->limitation != $limitation, 'limitation is copied, not aliased';
  is $info->fees, $fees, 'fees content is preserved';
  ok $info->fees != $fees, 'fees are copied, not aliased';
  is $info->overnet->{core_version}, '0.1.0', 'overnet metadata is preserved';

  my $bare = Overnet::Relay::Info->new(name => 'bare');
  is $bare->supported_nips, [],    'missing supported NIPs default to an empty list';
  is $bare->limitation,     undef, 'missing limitation stays undefined';
  is $bare->fees,           undef, 'missing fees stay undefined';
  is $bare->overnet,        undef, 'missing overnet metadata stays undefined';

  my $malformed = Overnet::Relay::Info->new(
    name       => 'malformed structs',
    limitation => 'not-a-hash',
    fees       => ['not-a-hash'],
    overnet    => 'not-a-hash',
  );
  is $malformed->limitation, undef, 'non-hash limitation is dropped';
  is $malformed->fees,       undef, 'non-hash fees are dropped';
  is $malformed->overnet,    undef, 'non-hash overnet metadata is dropped';
};

subtest 'to_hash includes only defined fields' => sub {
  my $full = Overnet::Relay::Info->new(
    name             => 'Full Relay',
    description      => 'documented',
    banner           => 'https://banner.example.test',
    icon             => 'https://icon.example.test',
    pubkey           => 'a' x 64,
    self             => 'b' x 64,
    contact          => 'admin@example.test',
    software         => 'https://software.example.test',
    version          => '1.0.0',
    terms_of_service => 'https://tos.example.test',
    payments_url     => 'https://pay.example.test',
    supported_nips   => [1, 11],
    limitation       => {max_limit => 5},
    fees             => {admission => []},
    overnet          => {relay_profile => 'volunteer-basic'},
  );
  my $doc = $full->to_hash;
  is $doc->{name},   'Full Relay', 'scalar fields are included';
  is $doc->{pubkey}, 'a' x 64,     'admin pubkey is included';
  is $doc->{supported_nips}, [1, 11], 'supported NIPs are included';
  is $doc->{limitation}, {max_limit => 5},  'limitation is included';
  is $doc->{fees},       {admission => []}, 'fees are included';
  is $doc->{overnet}{relay_profile}, 'volunteer-basic', 'overnet metadata is included';

  my $sparse = Overnet::Relay::Info->new(name => 'Sparse Relay');
  is $sparse->to_hash,
    {name => 'Sparse Relay'},
    'undefined scalar and structured fields are omitted entirely';
};

subtest 'HTTP rendering wraps the canonical JSON document' => sub {
  my $info = Overnet::Relay::Info->new(name => 'HTTP Relay', supported_nips => [11]);

  is $JSON->decode($info->to_json), $info->to_hash, 'to_json matches to_hash';

  my $response = $info->to_http_response;
  like $response, qr/\AHTTP\/1\.1\ 200\ OK\r\n/mx, 'info response is an HTTP 200';
  like $response, qr/Content-Type:\ application\/nostr\+json/mx, 'NIP-11 content type is used';
  my (undef, $body) = split /\r\n\r\n/mx, $response, 2;
  is $JSON->decode($body), $info->to_hash, 'response body is the info document';
  like $response, qr/Content-Length:\ @{[length $body]}/mx, 'content length matches the body';

  my $preflight = Overnet::Relay::Info::cors_preflight_response();
  like $preflight, qr/\AHTTP\/1\.1\ 204\ No\ Content\r\n/mx, 'preflight is an HTTP 204';
  like $preflight, qr/Access-Control-Allow-Origin:\ \*/mx,   'preflight allows any origin';
  like $preflight, qr/Content-Length:\ 0/mx,                 'preflight has no body';
};

done_testing;
