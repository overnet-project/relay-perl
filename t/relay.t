use strict;
use warnings;

use JSON::PP ();
use Test::More;

use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Message;
use Net::Nostr::Negentropy;
use Overnet::Relay;

my $JSON = JSON::PP->new->utf8->canonical;

subtest 'NIP-11 info includes Overnet metadata' => sub {
  my $relay = _build_relay();
  my $body = $relay->relay_info->to_hash;

  is $body->{name}, 'Overnet Test Relay', 'relay info name';
  ok grep($_ == 77, @{$body->{supported_nips} || []}), 'supported_nips includes 77';
  ok grep($_ eq 'overnet.events.sync', @{$body->{overnet}{capabilities} || []}),
    'capabilities include overnet.events.sync';
  is $body->{overnet}{limits}{max_negentropy_sessions}, 4,
    'overnet limits expose negentropy session limit';
};

my $author = Net::Nostr::Key->new;
my $valid_event = _create_overnet_event(
  key => $author,
  kind => 7800,
  event_type => 'chat.message',
  object_type => 'chat.channel',
  object_id => 'irc:local:#overnet',
  body => { text => 'hello relay' },
);

subtest 'publishes a valid Overnet event' => sub {
  my $relay = _build_relay();
  my $conn = $relay->_connections->{1};

  $relay->_handle_event(1, $valid_event);

  my $ok = _last_message_of_type($conn, 'OK');
  ok $ok, 'received publish result';
  is $ok->event_id, $valid_event->id, 'publish result references event id';
  ok $ok->accepted, 'event accepted';
  like $ok->message, qr/\Aaccepted:/, 'accept result uses accepted prefix';
  is $relay->store->get_by_id($valid_event->id)->id, $valid_event->id,
    'event stored in relay store';
};

my $invalid_missing_mirror = $author->create_event(
  kind => 7800,
  tags => [
    ['overnet_v', '0.1.0'],
    ['overnet_et', 'chat.message'],
    ['overnet_ot', 'chat.channel'],
    ['overnet_oid', 'irc:local:#overnet'],
  ],
  content => $JSON->encode({
    provenance => { type => 'native' },
    body => { text => 'missing mirror tags' },
  }),
);

subtest 'rejects events missing mirror tags' => sub {
  my $relay = _build_relay();
  my $conn = $relay->_connections->{1};

  $relay->_handle_event(1, $invalid_missing_mirror);

  my $ok = _last_message_of_type($conn, 'OK');
  ok $ok, 'received rejection result';
  ok !$ok->accepted, 'event rejected';
  like $ok->message, qr/\Ainvalid:\s+Missing required v tag/,
    'rejects missing mirror tags';
  ok !$relay->store->get_by_id($invalid_missing_mirror->id),
    'invalid event not stored';
};

subtest 'supports canonical Overnet tag queries over REQ' => sub {
  my $relay = _build_relay();
  my $conn = $relay->_connections->{1};
  $relay->store->store($valid_event);

  my $filter = Net::Nostr::Filter->new(
    kinds => [7800],
    '#overnet_et' => ['chat.message'],
    '#overnet_ot' => ['chat.channel'],
    '#overnet_oid' => ['irc:local:#overnet'],
  );
  $relay->_handle_req(1, 'sub-overnet', $filter);

  my @messages = map { Net::Nostr::Message->parse($_) } @{$conn->sent_messages};
  my ($event_msg) = grep { $_->type eq 'EVENT' } @messages;
  my ($eose_msg) = grep { $_->type eq 'EOSE' } @messages;

  ok $event_msg, 'query returned an EVENT frame';
  is $event_msg->subscription_id, 'sub-overnet', 'subscription id matches';
  is $event_msg->event->id, $valid_event->id, 'query returned the published event';
  ok $eose_msg, 'query returned EOSE';
  is $eose_msg->subscription_id, 'sub-overnet', 'EOSE subscription id matches';
};

my $state_event = _create_overnet_event(
  key => $author,
  kind => 37800,
  event_type => 'chat.topic',
  object_type => 'chat.channel',
  object_id => 'irc:local:#overnet',
  body => { text => 'Relay Topic' },
);

subtest 'object-read endpoint returns current state view' => sub {
  my $relay = _build_relay();
  $relay->store->store($state_event);

  my $response = $relay->_handle_object_http_request(
    'GET',
    '/.well-known/overnet/v1/object?type=chat.channel&id=irc%3Alocal%3A%23overnet',
  );

  like $response, qr/\AHTTP\/1\.[01] 200 /, 'returns HTTP 200';
  my $body = _decode_http_json_body($response);
  is $body->{object_type}, 'chat.channel', 'object type matches';
  is $body->{object_id}, 'irc:local:#overnet', 'object id matches';
  ok !$body->{removed}, 'object is not removed';
  is $body->{state_event}{id}, $state_event->id, 'returns latest state event';
  is $body->{removal_event}, undef, 'no removal event present';
};

subtest 'supports negentropy reconciliation with mirror-tag filters' => sub {
  my $relay = _build_relay();
  my $conn = $relay->_connections->{1};
  $relay->store->store($state_event);

  my $ne = Net::Nostr::Negentropy->new;
  $ne->seal;

  my $filter = Net::Nostr::Filter->new(
    kinds => [37800],
    '#t' => ['chat.topic'],
    '#o' => ['chat.channel'],
    '#d' => ['irc:local:#overnet'],
  );

  my $msg = Net::Nostr::Message->new(
    type => 'NEG-OPEN',
    subscription_id => 'neg-overnet',
    filter => $filter,
    neg_msg => $ne->initiate,
  );
  $relay->_handle_neg_open(1, $msg);

  my $neg_msg = _last_message_of_type($conn, 'NEG-MSG');
  ok $neg_msg, 'received negentropy response';

  my ($next, $have, $need) = $ne->reconcile($neg_msg->neg_msg);
  is_deeply $have, [], 'empty client has nothing the relay lacks';
  is_deeply $need, [$state_event->id], 'relay reports the state event as needed';
};

done_testing;

sub _build_relay {
  my $relay = Overnet::Relay->new(
    name => 'Overnet Test Relay',
    description => 'Test relay for Overnet integration coverage',
    software => 'https://example.invalid/overnet-relay',
    version => '0.1.0-test',
    max_filters => 8,
    max_limit => 100,
    max_subscriptions => 8,
    max_negentropy_sessions => 4,
    max_message_length => 65536,
    max_content_length => 32768,
  );

  $relay->_connections({ 1 => _TestConn->new });
  $relay->_subscriptions({ 1 => {} });
  $relay->_authenticated({ 1 => {} });
  $relay->_rate_state({});
  $relay->_neg_sessions({ 1 => {} });
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});

  return $relay;
}

sub _create_overnet_event {
  my (%args) = @_;
  my $key = delete $args{key};
  my $kind = delete $args{kind};
  my $event_type = delete $args{event_type};
  my $object_type = delete $args{object_type};
  my $object_id = delete $args{object_id};
  my $body = delete $args{body};

  my @tags = (
    ['overnet_v', '0.1.0'],
    ['overnet_et', $event_type],
    ['overnet_ot', $object_type],
    ['overnet_oid', $object_id],
    ['v', '0.1.0'],
    ['t', $event_type],
    ['o', $object_type],
    ['d', $object_id],
  );

  return $key->create_event(
    kind => $kind,
    tags => \@tags,
    content => $JSON->encode({
      provenance => { type => 'native' },
      body => $body,
    }),
  );
}

sub _last_message_of_type {
  my ($conn, $type) = @_;
  for my $raw (reverse @{$conn->sent_messages}) {
    my $msg = Net::Nostr::Message->parse($raw);
    return $msg if $msg->type eq $type;
  }
  return undef;
}

sub _decode_http_json_body {
  my ($response) = @_;
  my (undef, $body) = split /\r\n\r\n/, $response, 2;
  return $JSON->decode($body);
}

{
  package _TestConn;

  sub new {
    return bless { sent_messages => [] }, shift;
  }

  sub send {
    my ($self, $message) = @_;
    push @{$self->{sent_messages}}, $message;
    return $self;
  }

  sub sent_messages {
    my ($self) = @_;
    return $self->{sent_messages};
  }
}
