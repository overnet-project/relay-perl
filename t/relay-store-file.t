use strictures 2;

use File::Temp qw(tempdir);
use JSON       ();
use Test2::V0;

use Net::Nostr::Key;
use Overnet::Relay::Store::File;

my $JSON = JSON->new->utf8->canonical;
my $KEY  = Net::Nostr::Key->new;

sub _event {
  my (%args) = @_;
  return $KEY->create_event(
    kind       => exists $args{kind}       ? $args{kind}       : 1,
    created_at => exists $args{created_at} ? $args{created_at} : 1_700_000_000,
    content    => exists $args{content}    ? $args{content}    : 'payload',
    tags       => exists $args{tags}       ? $args{tags}       : [],
  );
}

sub _lines {
  my ($path) = @_;
  open my $fh, '<:raw', $path or die "open $path: $!";
  my $raw = do { local $/ = undef; <$fh> };
  close $fh;
  if (!(defined $raw && length $raw)) {
    return [];
  }
  return [split /\n/mx, $raw];
}

sub _ids {
  my ($store) = @_;
  return [sort map { $_->id } @{$store->all_events || []}];
}

subtest 'appends one record per store instead of rewriting the whole file' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = "$dir/store.json";
  my $store = Overnet::Relay::Store::File->new(path => $path);

  $store->store(_event(content => 'one', created_at => 1_700_000_001));
  my $after_one = _lines($path);
  is scalar(@{$after_one}), 1, 'one record line after first store';
  my $first_line = $after_one->[0];

  $store->store(_event(content => 'two', created_at => 1_700_000_002));
  my $after_two = _lines($path);
  is scalar(@{$after_two}), 2,           'second store appends a second line';
  is $after_two->[0],       $first_line, 'the first record is not rewritten on the second store';
};

subtest 'round-trips stored events across reload' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my @events = map { _event(content => "e$_", created_at => 1_700_000_000 + $_) } (1 .. 3);
  my $store  = Overnet::Relay::Store::File->new(path => $path);
  $store->store($_) for @events;

  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is _ids($reloaded), [sort map { $_->id } @events], 'reloaded store has the same events';
};

subtest 'a delete tombstone survives reload' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my $keep   = _event(content => 'keep',   created_at => 1_700_000_010);
  my $remove = _event(content => 'remove', created_at => 1_700_000_011);

  my $store = Overnet::Relay::Store::File->new(path => $path);
  $store->store($keep);
  $store->store($remove);
  $store->delete_by_id($remove->id);

  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is _ids($reloaded), [$keep->id], 'deleted event does not come back after reload';
};

subtest 'loads the legacy single-array store format' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my @events = map { _event(content => "legacy$_", created_at => 1_700_000_020 + $_) } (1 .. 2);
  open my $fh, '>:raw', $path or die "open $path: $!";
  print {$fh} $JSON->encode([map { $_->to_hash } @events]) or die "write $path: $!";
  close $fh;

  my $store = Overnet::Relay::Store::File->new(path => $path);
  is _ids($store), [sort map { $_->id } @events], 'legacy array format loads all events';

  # The first write normalizes the legacy file, and subsequent writes append.
  my $added = _event(content => 'legacy-add', created_at => 1_700_000_099);
  $store->store($added);
  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is _ids($reloaded), [sort map { $_->id } (@events, $added)], 'normalized store keeps legacy plus new events';
};

subtest 'compacts the log so the file stays bounded under churn' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my $store = Overnet::Relay::Store::File->new(path => $path);
  my @all   = map { _event(content => "c$_", created_at => 1_700_100_000 + $_) } (0 .. 299);
  $store->store($_) for @all;
  $store->delete_by_id($all[$_]->id) for (0 .. 249);

  my $live = 300 - 250;
  is scalar(@{$store->all_events}), $live, 'live event count is correct after churn';

  my $lines = _lines($path);
  ok scalar(@{$lines}) < 550, 'compaction keeps the file well below the total operation count'
    or diag 'line count: ' . scalar(@{$lines});

  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is scalar(@{$reloaded->all_events}), $live, 'reloaded store matches the live set after compaction';
};

subtest 'clear empties the persisted store' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my $store = Overnet::Relay::Store::File->new(path => $path);
  $store->store(_event(content => 'gone', created_at => 1_700_000_030));
  $store->clear;

  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is scalar(@{$reloaded->all_events}), 0, 'cleared store is empty after reload';
};

subtest 'max_events eviction persists across reload' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my $store  = Overnet::Relay::Store::File->new(path => $path, max_events => 2);
  my @events = map { _event(content => "m$_", created_at => 1_700_000_040 + $_) } (1 .. 3);
  $store->store($_) for @events;

  is scalar(@{$store->all_events}), 2, 'store retains only max_events events';

  my $reloaded = Overnet::Relay::Store::File->new(path => $path, max_events => 2);
  is _ids($reloaded), _ids($store), 'reloaded store matches the evicted live set';
};

done_testing;
