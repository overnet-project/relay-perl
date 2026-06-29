use strictures 2;

use JSON ();
use Test::More;

use Net::Nostr::Key;
use Net::Nostr::Message;
use Overnet::Relay;

my $JSON   = JSON->new->utf8->canonical;
my $author = Net::Nostr::Key->new;

subtest 'profile validation is off by default without configured contracts' => sub {
  my $relay = _build_relay();
  my $event = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'custom.event',
    object_type => 'custom.object',
    object_id   => 'custom:1',
    body        => {any => 'shape'},
  );

  is $relay->profile_contract_policy, 'off', 'default policy is off without contracts';
  my $ok = _publish($relay, $event);
  ok $ok->accepted, 'core-valid event with no configured contract remains accepted';
};

subtest 'configured contracts default to known policy and validate matching events only' => sub {
  my $relay = _build_relay(profile_contracts => [_chat_contract()]);

  is $relay->profile_contract_policy, 'known', 'configured contracts default to known';

  my $valid = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'valid'},
  );
  ok _publish($relay, $valid)->accepted, 'matching valid profile event is accepted';

  my $invalid = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 42},
  );
  my $invalid_ok = _publish($relay, $invalid);
  ok !$invalid_ok->accepted, 'matching invalid profile event is rejected';
  like $invalid_ok->message, qr/\Ainvalid:\s+profile_event\.body_schema_mismatch/mx,
    'profile rejection uses invalid outcome reason';

  my $unknown = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.notice',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 42},
  );
  ok _publish($relay, $unknown)->accepted, 'known policy accepts events whose event type is not configured';

  my $info = $relay->relay_info->to_hash->{overnet}{profile_contracts};
  is $info->{policy}, 'known', 'metadata advertises policy';
  ok $info->{configured}, 'metadata advertises configured contracts';
  ok $info->{enforced},   'metadata advertises enforcement';
  is_deeply $info->{profiles},    ['chat'],         'metadata advertises configured profiles';
  is_deeply $info->{event_types}, ['chat.message'], 'metadata advertises configured event types';
};

subtest 'off policy keeps configured contracts non-enforcing' => sub {
  my $relay = _build_relay(
    profile_contract_policy => 'off',
    profile_contracts       => [_chat_contract()],
  );

  my $invalid = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.message',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 42},
  );

  is $relay->profile_contract_policy, 'off', 'explicit policy is kept';
  ok _publish($relay, $invalid)->accepted, 'off policy accepts core-valid events even when contract would reject them';
  ok !$relay->relay_info->to_hash->{overnet}{profile_contracts}{enforced},
    'metadata advertises configured but non-enforced contracts';
};

subtest 'required policy rejects profile events without a configured contract' => sub {
  my $relay = _build_relay(
    profile_contract_policy => 'required',
    profile_contracts       => [_chat_contract()],
  );

  my $unknown = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'chat.notice',
    object_type => 'chat.channel',
    object_id   => 'irc:local:#overnet',
    body        => {text => 'notice'},
  );

  my $ok = _publish($relay, $unknown);
  ok !$ok->accepted, 'required policy rejects events without matching contract';
  like $ok->message, qr/\Ainvalid:\s+profile_event\.event_type_undefined/mx,
    'missing profile contract uses invalid reason';

  my $unknown_core = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'core.experimental',
    object_type => 'core.object',
    object_id   => 'core:1',
    body        => {text => 'not a defined core protocol event'},
  );

  my $unknown_core_ok = _publish($relay, $unknown_core);
  ok !$unknown_core_ok->accepted, 'required policy rejects unknown core-prefixed event types';
  like $unknown_core_ok->message, qr/\Ainvalid:\s+profile_event\.event_type_undefined/mx,
    'unknown core-prefixed events do not bypass required policy';

  my $delegation = _create_overnet_event(
    key         => $author,
    kind        => 7800,
    event_type  => 'core.delegation',
    object_type => 'core.delegation',
    object_id   => 'core:delegation:1',
    body        => {
      action          => 'remove',
      delegate_pubkey => Net::Nostr::Key->new->pubkey_hex,
    },
  );

  ok _publish($relay, $delegation)->accepted, 'required policy leaves defined core protocol events to core validation';
};

subtest 'core validation runs before profile validation' => sub {
  my $relay = _build_relay(profile_contracts => [_chat_contract()]);
  my $event = $author->create_event(
    kind => 7800,
    tags => _overnet_tags(
      event_type  => 'chat.message',
      object_type => 'chat.channel',
      object_id   => 'irc:local:#overnet',
    ),
    content => $JSON->encode({provenance => {type => 'native'}}),
  );

  my $ok = _publish($relay, $event);
  ok !$ok->accepted, 'event is rejected';
  like $ok->message, qr/\Ainvalid:\s+Missing\ required\ body\ field\ in\ content/mx,
    'core validation reason wins before profile checks';
};

subtest 'contracts are validated at relay construction time' => sub {
  my $contract = _chat_contract();
  delete $contract->{event_types}{'chat.message'}{body_schema};

  my $relay = eval { _build_relay(profile_contracts => [$contract]) };
  my $error = $@;
  ok !$relay, 'relay construction fails';
  like $error, qr/profile_contract\./mx, 'invalid contract is rejected before publish';
};

done_testing;

sub _build_relay {
  my (%args) = @_;
  my $relay = Overnet::Relay->new(
    name                    => 'Overnet Test Relay',
    description             => 'Test relay for Overnet profile contract coverage',
    software                => 'https://example.invalid/overnet-relay',
    version                 => '0.1.0-test',
    max_filters             => 8,
    max_limit               => 100,
    max_subscriptions       => 8,
    max_negentropy_sessions => 4,
    max_message_length      => 65536,
    max_content_length      => 32768,
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

sub _publish {
  my ($relay, $event) = @_;
  my $conn = $relay->_connections->{1};
  $relay->_handle_event(1, $event);
  return _last_message_of_type($conn, 'OK');
}

sub _create_overnet_event {
  my (%args) = @_;
  my $key    = delete $args{key};
  my $kind   = delete $args{kind};
  my $body   = delete $args{body};

  return $key->create_event(
    kind    => $kind,
    tags    => _overnet_tags(%args),
    content => $JSON->encode(
      {
        provenance => {type => 'native'},
        body       => $body,
      }
    ),
  );
}

sub _overnet_tags {
  my (%args)      = @_;
  my $event_type  = delete $args{event_type};
  my $object_type = delete $args{object_type};
  my $object_id   = delete $args{object_id};

  return [
    ['overnet_v',   '0.1.0'],
    ['overnet_et',  $event_type],
    ['overnet_ot',  $object_type],
    ['overnet_oid', $object_id],
    ['v',           '0.1.0'],
    ['t',           $event_type],
    ['o',           $object_type],
    ['d',           $object_id],
  ];
}

sub _chat_contract {
  return {
    contract_version => 1,
    profile          => 'chat',
    profile_version  => '1.0.0',
    status           => 'stable',
    description      => 'Chat profile contract',
    capabilities     => ['chat.messaging'],
    object_types     => {
      'chat.channel' => {
        description => 'Chat channel',
        id          => {
          scheme   => 'uri',
          pattern  => undef,
          examples => ['irc:local:#overnet'],
        },
        state => {
          derivation       => 'event-log',
          state_event_type => undef,
        },
        extensions => {},
      },
    },
    event_types => {
      'chat.message' => {
        description   => 'Chat message',
        kind          => 7800,
        object_type   => 'chat.channel',
        required_tags => [qw(overnet_v overnet_et overnet_ot overnet_oid v t o d)],
        body_schema   => {
          type       => 'object',
          required   => ['text'],
          properties => {
            text => {type => 'string'},
          },
          additionalProperties => JSON::false,
        },
        references    => [],
        state_effect  => 'updates',
        authorization => {
          model       => 'open',
          description => 'Any author may write chat messages',
        },
        privacy    => 'public',
        extensions => {},
      },
    },
    fixtures => {
      valid   => [],
      invalid => [],
    },
    extensions => {},
  };
}

sub _last_message_of_type {
  my ($conn, $type) = @_;
  for my $raw (reverse @{$conn->sent_messages}) {
    my $msg = Net::Nostr::Message->parse($raw);
    return $msg if $msg->type eq $type;
  }
  return;
}

{

  package _TestConn;

  sub new {
    return bless {sent_messages => []}, shift;
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
