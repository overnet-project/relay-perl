use strictures 2;

use JSON ();
use Test2::V0;

use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Message;
use Net::Nostr::Negentropy;
use Overnet::Relay::Deploy;

my $JSON   = JSON->new->utf8->canonical;
my $author = Net::Nostr::Key->new;

{

  package _TestConn;

  use Moo;

  has sent_messages => (is => 'ro', reader => '_sent_messages', default => sub { [] });

  no Moo;

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


sub _build_deploy_relay {
  my (%args) = @_;
  my $relay = Overnet::Relay::Deploy->new(
    relay_url               => 'ws://deploy.example.test',
    profile_contract_policy => 'off',
    %args,
  );

  $relay->_connections({1 => _TestConn->new});
  $relay->_subscriptions({1 => {}});
  $relay->_authenticated({1 => {}});
  $relay->_rate_state({});
  $relay->_neg_sessions({1 => {}});
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});

  return $relay;
}

sub _create_overnet_event {
  my (%args) = @_;
  my @tags   = (
    ['overnet_v',   '0.1.0'],
    ['overnet_et',  'chat.message'],
    ['overnet_ot',  'chat.channel'],
    ['overnet_oid', 'irc:local:#overnet'],
    ['v',           '0.1.0'],
    ['t',           'chat.message'],
    ['o',           'chat.channel'],
    ['d',           'irc:local:#overnet'],
  );

  return $author->create_event(
    kind    => exists $args{kind} ? $args{kind} : 7800,
    tags    => \@tags,
    content => $JSON->encode(
      {
        provenance => {type => 'native'},
        body       => {text => exists $args{text} ? $args{text} : 'deploy policy test'},
      }
    ),
  );
}

sub _last_message_of_type {
  my ($conn, $type) = @_;
  for my $raw (reverse @{$conn->sent_messages}) {
    my $msg = Net::Nostr::Message->parse($raw);
    return $msg if $msg->type eq $type;
  }
  return;
}

sub _neg_open_message {
  my ($ne) = @_;
  return Net::Nostr::Message->new(
    type            => 'NEG-OPEN',
    subscription_id => 'neg-deploy',
    filter          => Net::Nostr::Filter->new(kinds => [7800]),
    neg_msg         => $ne->initiate,
  );
}

subtest 'publish policies gate EVENT handling' => sub {
  my $event = _create_overnet_event();

  my $closed = _build_deploy_relay(service_policies => {publish => 'closed'});
  $closed->_handle_event(1, $event);
  my $closed_ok = _last_message_of_type($closed->_connections->{1}, 'OK');
  ok $closed_ok, 'closed publish returns an OK frame';
  ok !$closed_ok->accepted, 'closed publish is rejected';
  is $closed_ok->event_id, $event->id, 'closed publish rejection references the event id';
  like $closed_ok->message, qr/\Apolicy_denied:/mx, 'closed publish uses the policy_denied prefix';
  ok !$closed->store->get_by_id($event->id), 'closed publish does not store the event';

  my $paid = _build_deploy_relay(service_policies => {publish => 'paid'});
  $paid->_handle_event(1, $event);
  my $paid_ok = _last_message_of_type($paid->_connections->{1}, 'OK');
  ok !$paid_ok->accepted, 'paid publish is rejected without payment';
  like $paid_ok->message, qr/\Apayment_required:/mx, 'paid publish uses the payment_required prefix';

  my $auth = _build_deploy_relay(service_policies => {publish => 'auth'});
  $auth->_handle_event(1, $event);
  my $auth_ok = _last_message_of_type($auth->_connections->{1}, 'OK');
  ok !$auth_ok->accepted, 'auth publish is rejected for unauthenticated connections';
  like $auth_ok->message, qr/\Aunauthorized:/mx, 'auth publish uses the unauthorized prefix';

  my $authed = _build_deploy_relay(service_policies => {publish => 'auth'});
  $authed->_authenticated({1 => {$author->pubkey_hex => 1}});
  $authed->_handle_event(1, $event);
  my $authed_ok = _last_message_of_type($authed->_connections->{1}, 'OK');
  ok $authed_ok->accepted, 'auth publish is accepted for authenticated connections';
  is $authed->store->get_by_id($event->id)->id, $event->id, 'authenticated publish stores the event';

  my $open = _build_deploy_relay();
  $open->_handle_event(1, $event);
  my $open_ok = _last_message_of_type($open->_connections->{1}, 'OK');
  ok $open_ok->accepted, 'open publish falls through to normal event handling';
};

subtest 'query and subscribe policies gate REQ handling' => sub {
  my $filter = sub { Net::Nostr::Filter->new(kinds => [7800]) };

  my $closed_query = _build_deploy_relay(service_policies => {query => 'closed'});
  $closed_query->_handle_req(1, 'sub-closed', $filter->());
  my $closed_msg = _last_message_of_type($closed_query->_connections->{1}, 'CLOSED');
  ok $closed_msg, 'closed query returns a CLOSED frame';
  is $closed_msg->subscription_id, 'sub-closed', 'CLOSED frame references the subscription';
  like $closed_msg->message, qr/\Apolicy_denied:/mx, 'closed query uses the policy_denied prefix';

  my $auth_subscribe = _build_deploy_relay(service_policies => {subscribe => 'auth'});
  $auth_subscribe->_handle_req(1, 'sub-auth', $filter->());
  my $auth_msg = _last_message_of_type($auth_subscribe->_connections->{1}, 'CLOSED');
  ok $auth_msg, 'auth-gated subscribe returns a CLOSED frame when unauthenticated';
  like $auth_msg->message, qr/\Aunauthorized:/mx, 'auth-gated subscribe uses the unauthorized prefix';

  my $open  = _build_deploy_relay();
  my $event = _create_overnet_event(text => 'req fanout');
  $open->store->store($event);
  $open->_handle_req(1, 'sub-open', $filter->());
  my $conn      = $open->_connections->{1};
  my @messages  = map { Net::Nostr::Message->parse($_) } @{$conn->sent_messages};
  my @event_msg = grep { $_->type eq 'EVENT' } @messages;
  my @eose_msg  = grep { $_->type eq 'EOSE' } @messages;
  is scalar(@event_msg), 1, 'open REQ falls through and returns the stored event';
  is $event_msg[0]->event->id, $event->id, 'open REQ returns the stored event id';
  is scalar(@eose_msg), 1, 'open REQ returns EOSE';
};

subtest 'sync policy gates NEG-OPEN handling' => sub {
  my $closed = _build_deploy_relay(service_policies => {sync => 'closed'});
  my $ne     = Net::Nostr::Negentropy->new;
  $ne->seal;

  # KNOWN BUG: the sync denial path builds its NEG-ERR frame with code and
  # reason arguments that Net::Nostr::Message rejects, so a policy-denied
  # NEG-OPEN currently dies instead of sending NEG-ERR. This coverage-only
  # change set may not alter lib/ behavior, so pin the current behavior; the
  # eventual fix must update this assertion to expect a NEG-ERR frame.
  like dies { $closed->_handle_neg_open(1, _neg_open_message($ne)) },
    qr/unknown\ argument\(s\):\ code,\ reason/mx,
    'closed sync denial currently dies building its NEG-ERR frame';

  my $open    = _build_deploy_relay();
  my $open_ne = Net::Nostr::Negentropy->new;
  $open_ne->seal;
  $open->_handle_neg_open(1, _neg_open_message($open_ne));
  my $neg_msg = _last_message_of_type($open->_connections->{1}, 'NEG-MSG');
  ok $neg_msg, 'open sync falls through to negentropy reconciliation';
};

subtest 'object_read policy gates the object HTTP endpoint' => sub {
  my $closed = _build_deploy_relay(service_policies => {object_read => 'closed'});
  my $response = $closed->_handle_object_http_request('GET', '/.well-known/overnet/v1/object?type=a&id=b');
  like $response, qr/\AHTTP\/1\.1\ 403\ Forbidden/mx, 'closed object_read returns HTTP 403';
  like $response, qr/policy_denied/mx, 'closed object_read body carries the policy_denied code';

  my $auth = _build_deploy_relay(service_policies => {object_read => 'auth'});
  $response = $auth->_handle_object_http_request('GET', '/.well-known/overnet/v1/object?type=a&id=b');
  like $response, qr/\AHTTP\/1\.1\ 401\ Unauthorized/mx,
    'auth object_read returns HTTP 401 because HTTP requests carry no connection';
  like $response, qr/unauthorized/mx, 'auth object_read body carries the unauthorized code';

  my $paid = _build_deploy_relay(service_policies => {object_read => 'paid'});
  $response = $paid->_handle_object_http_request('GET', '/.well-known/overnet/v1/object?type=a&id=b');
  like $response, qr/\AHTTP\/1\.1\ 402\ Payment\ Required/mx, 'paid object_read returns HTTP 402';
  like $response, qr/payment_required/mx, 'paid object_read body carries the payment_required code';

  my $open = _build_deploy_relay();
  $response = $open->_handle_object_http_request('GET', '/.well-known/overnet/v1/object?type=a&id=b');
  like $response, qr/\AHTTP\/1\.1\ 404\ Not\ Found/mx,
    'open object_read falls through to the normal object endpoint';
};

subtest 'service policy helpers cover degenerate inputs' => sub {
  my $relay = _build_deploy_relay();

  $relay->service_policies(undef);
  is $relay->_service_policy_message('publish', 1), undef,
    'a missing policy map behaves as open';
  $relay->service_policies({});
  is $relay->_service_policy_message('publish', 1), undef,
    'a missing service entry behaves as open';

  is $relay->_service_policy_http_error('object_read'), undef,
    'open object_read produces no HTTP error response';

  my $body = $relay->_service_policy_http_body('weird message without prefix');
  is $JSON->decode($body)->{error}{code}, 'policy_denied',
    'unprefixed policy messages fall back to the policy_denied code';

  is $relay->_connection_is_authenticated(undef), 0,
    'undefined connection ids are unauthenticated';
  $relay->_authenticated({1 => 'not-a-hash'});
  is $relay->_connection_is_authenticated(1), 0,
    'non-hash authentication state is unauthenticated';
  $relay->_authenticated({1 => {}});
  is $relay->_connection_is_authenticated(1), 0,
    'empty authentication state is unauthenticated';
  $relay->_authenticated({1 => {abc => 1}});
  is $relay->_connection_is_authenticated(1), 1,
    'a connection with an authenticated pubkey is authenticated';
};

done_testing;

