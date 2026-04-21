requires 'Net::Nostr';
requires 'Class::Tiny';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
