use strictures 2;

use Test2::V0;

use Net::Nostr::Event;
use Overnet::Authority::HostedChannel::Relay ();

# Section 11.4 of the IRC adapter spec requires authoritative group state to be
# derived from one deterministic total order that does NOT depend on relay
# delivery order or local input-array position. When two authoritative events
# remain tied after created_at, per-session causal order, and semantic phase,
# the tie MUST break by ascending lowercase Nostr event id. This test feeds the
# same accepted events to the derivation in opposite store orders and asserts
# the derived state converges, and that the surviving write is the one selected
# by event id rather than by whichever event happened to be stored last.

my $GROUP_ID  = 'localnet-overnet';
my $TARGET    = 'a' x 64;
my $AUTHORITY = 'b' x 64;
my $BASE_TIME = 1_750_000_000;

# A store double: the derivation only ever asks it for every stored event.
{

  package DerivationTest::Store;
  sub new { my ($class, @events) = @_; return bless {events => [@events]}, $class; }
  sub all_events { my ($self) = @_; return $self->{events}; }
}
{

  package DerivationTest::Relay;
  sub new { my ($class, $store) = @_; return bless {store => $store}, $class; }
  sub store { my ($self) = @_; return $self->{store}; }
}

sub _put_user_event {
  my (%args) = @_;
  my @tags = (['h', $GROUP_ID], ['p', $TARGET, @{$args{roles} || []}]);
  if (defined $args{authority}) {
    push @tags, ['overnet_authority', $args{authority}];
  }
  if (defined $args{sequence}) {
    push @tags, ['overnet_sequence', $args{sequence}];
  }
  return Net::Nostr::Event->new(
    pubkey     => $args{signer},
    kind       => 9_000,
    created_at => $args{created_at},
    tags       => \@tags,
    content    => $args{content} // q{},
  );
}

sub _derived_roles {
  my (@events) = @_;
  my $relay    = DerivationTest::Relay->new(DerivationTest::Store->new(@events));
  my $state    = Overnet::Authority::HostedChannel::Relay::_derive_group_state(
    relay    => $relay,
    group_id => $GROUP_ID,
  );
  my $member = $state->{members}{$TARGET};
  return $member ? $member->{roles} : undef;
}

subtest 'same-second put-user conflict converges regardless of store order' => sub {
  my $operator = _put_user_event(
    signer     => 'c' x 64,
    created_at => $BASE_TIME,
    roles      => ['irc.operator'],
    content    => 'grant-operator',
  );
  my $plain = _put_user_event(
    signer     => 'd' x 64,
    created_at => $BASE_TIME,
    roles      => [],
    content    => 'demote-to-member',
  );

  my $forward = _derived_roles($operator, $plain);
  my $reverse = _derived_roles($plain,    $operator);

  is $forward, $reverse, 'derived roles are identical in both store orders';

  # Last-writer-wins over an ascending-event-id order means the greater id wins.
  my $winner = (lc($operator->id) cmp lc($plain->id)) > 0 ? $operator : $plain;
  my @roles  = @{$winner->tags->[1]}[2 .. $#{$winner->tags->[1]}];
  is $forward, [@roles], 'the surviving write is the one chosen by ascending event id';
};

subtest 'same-session same-sequence conflict converges regardless of store order' => sub {
  my $operator = _put_user_event(
    signer     => 'c' x 64,
    created_at => $BASE_TIME,
    authority  => $AUTHORITY,
    sequence   => '1',
    roles      => ['irc.operator'],
    content    => 'grant-operator',
  );
  my $plain = _put_user_event(
    signer     => 'd' x 64,
    created_at => $BASE_TIME,
    authority  => $AUTHORITY,
    sequence   => '1',
    roles      => [],
    content    => 'demote-to-member',
  );

  my $forward = _derived_roles($operator, $plain);
  my $reverse = _derived_roles($plain,    $operator);

  is $forward, $reverse, 'a duplicated per-session sequence still converges by event id';
};

done_testing;
