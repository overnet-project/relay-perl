requires 'strictures', '2';
requires 'Net::Nostr';
requires 'Class::Tiny';
requires 'JSON';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
