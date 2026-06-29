requires 'strictures', '2';
requires 'Net::Nostr';
requires 'Class::Tiny';
requires 'JSON';
requires 'Package::Stash';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
