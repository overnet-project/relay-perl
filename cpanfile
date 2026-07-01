requires 'strictures', '2';
requires 'Net::Nostr';
requires 'Moo';
requires 'JSON';
requires 'Package::Stash';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
