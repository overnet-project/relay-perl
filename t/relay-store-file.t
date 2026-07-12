use strictures 2;

use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use JSON ();
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

subtest 'constructor validates argument shapes' => sub {
  my $dir = tempdir(CLEANUP => 1);

  ok(Overnet::Relay::Store::File->new({path => "$dir/hashref.json"}), 'hashref arguments are accepted');
  like dies { Overnet::Relay::Store::File->new('odd') },
    qr/constructor\ arguments\ must\ be\ a\ hash\ or\ hash\ reference/mx,
    'odd argument lists are rejected';
  like dies { Overnet::Relay::Store::File->new }, qr/path\ is\ required/mx, 'a path is required';
  like dies { Overnet::Relay::Store::File->new(path => q{}) },
    qr/path\ is\ required/mx, 'an empty path is rejected';
  like dies { Overnet::Relay::Store::File->new(path => {}) },
    qr/path\ is\ required/mx, 'a ref path is rejected';
};

subtest 'duplicate stores and missing deletions append nothing' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = "$dir/store.json";
  my $store = Overnet::Relay::Store::File->new(path => $path);

  my $event = _event(content => 'once', created_at => 1_700_000_050);
  is $store->store($event), 1, 'the first store is accepted';
  ok !$store->store($event), 'a duplicate store is refused';
  is scalar(@{_lines($path)}), 1, 'the duplicate did not append a record';

  ok !$store->delete_by_id('f' x 64), 'deleting an unknown id reports nothing deleted';
  is scalar(@{_lines($path)}), 1, 'the missing deletion did not append a tombstone';
};

subtest 'load tolerates blank lines and a torn final record' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = "$dir/store.json";
  my $event = _event(content => 'survivor', created_at => 1_700_000_060);

  open my $fh, '>:raw', $path or die "open $path: $!";
  print {$fh} $JSON->encode([q{+}, $event->to_hash]) . "\n\n" . '["+", {"torn'
    or die "write $path: $!";
  close $fh;

  my $store = Overnet::Relay::Store::File->new(path => $path);
  is _ids($store), [$event->id], 'the intact record loads despite the blank and torn lines';

  my $added = _event(content => 'after torn', created_at => 1_700_000_061);
  $store->store($added);
  my $reloaded = Overnet::Relay::Store::File->new(path => $path);
  is _ids($reloaded), [sort ($event->id, $added->id)],
    'the first write normalizes the file and drops the torn tail';
};

subtest 'load rejects genuinely corrupt store files' => sub {
  my $dir = tempdir(CLEANUP => 1);

  my $_written = sub {
    my ($name, $content) = @_;
    my $path = "$dir/$name";
    open my $fh, '>:raw', $path or die "open $path: $!";
    print {$fh} $content or die "write $path: $!";
    close $fh;
    return $path;
  };

  my $event      = _event(content => 'trailer', created_at => 1_700_000_070);
  my $event_line = $JSON->encode([q{+}, $event->to_hash]) . "\n";

  my $torn_middle = $_written->('torn-middle.json', '["+", {"torn' . "\n" . $event_line);
  like dies { Overnet::Relay::Store::File->new(path => $torn_middle) },
    qr/Invalid\ relay\ store\ file/mx, 'an undecodable non-final line is corruption';

  my $non_array = $_written->('non-array.json', "{\"not\":\"a record\"}\n");
  like dies { Overnet::Relay::Store::File->new(path => $non_array) },
    qr/must\ contain\ array\ records/mx, 'a non-array record is rejected';

  my $unrecognized = $_written->('unrecognized.json', "[\"x\",\"y\"]\n");
  like dies { Overnet::Relay::Store::File->new(path => $unrecognized) },
    qr/contains\ an\ unrecognized\ record/mx, 'an unknown record tag is rejected';

  my $bad_tombstone = $_written->('bad-tombstone.json', "[\"-\",{}]\n");
  like dies { Overnet::Relay::Store::File->new(path => $bad_tombstone) },
    qr/contains\ an\ unrecognized\ record/mx, 'a tombstone without a scalar id is rejected';
};

subtest 'legacy loads skip junk entries and empty legacy stores stay appendable' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";

  my $event = _event(content => 'legacy junk sibling', created_at => 1_700_000_080);
  open my $fh, '>:raw', $path or die "open $path: $!";
  print {$fh} $JSON->encode([$event->to_hash, 'junk', 42]) . "\n" or die "write $path: $!";
  close $fh;

  my $store = Overnet::Relay::Store::File->new(path => $path);
  is _ids($store), [$event->id], 'non-hash entries inside a legacy array are skipped';

  my $empty_path = "$dir/empty-legacy.json";
  open my $empty_fh, '>:raw', $empty_path or die "open $empty_path: $!";
  print {$empty_fh} "[]\n" or die "write $empty_path: $!";
  close $empty_fh;

  my $empty_store = Overnet::Relay::Store::File->new(path => $empty_path);
  is scalar(@{$empty_store->all_events}), 0, 'an empty legacy array loads no events';

  my $added = _event(content => 'first real record', created_at => 1_700_000_081);
  $empty_store->store($added);
  my $reloaded = Overnet::Relay::Store::File->new(path => $empty_path);
  is _ids($reloaded), [$added->id], 'a store loaded from a recordless file accepts appends';
};

subtest 'unreadable store paths are reported' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = "$dir/store.sock";
  IO::Socket::UNIX->new(Local => $path, Listen => 1)
    or skip_all "Can't create a unix socket for the unreadable-path case: $!";

  like dies { Overnet::Relay::Store::File->new(path => $path) },
    qr/Can't\ open\ relay\ store\ file .* for\ reading/mx,
    'a path that exists but cannot be opened croaks on load';
};

subtest 'unopenable append paths are reported' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $event = _event(content => 'never lands', created_at => 1_700_000_090);

  my $dir_backed = Overnet::Relay::Store::File->new(path => "$dir/blocked");
  mkdir "$dir/blocked" or die "mkdir $dir/blocked: $!";
  like dies { $dir_backed->store($event) },
    qr/Can't\ open\ relay\ store\ file .* for\ appending/mx,
    'an unopenable store path croaks on append';
};

subtest 'append write failures are reported' => sub {
  skip_all 'no writable /dev/full fault-injection device'
    if !(-c '/dev/full' && -w '/dev/full');

  my $dir   = tempdir(CLEANUP => 1);
  my $event = _event(content => 'never lands', created_at => 1_700_000_091);

  my $close_fail = Overnet::Relay::Store::File->new(path => "$dir/close-fail.json");
  $close_fail->path('/dev/full');
  like dies { $close_fail->store($event) },
    qr/Can't\ close\ relay\ store\ file .* after\ appending/mx,
    'a small append croaks when the flush at close fails';

  my $print_fail = Overnet::Relay::Store::File->new(path => "$dir/print-fail.json");
  $print_fail->path('/dev/full');
  my $oversized = _event(content => 'x' x 70_000, created_at => 1_700_000_092);
  like dies { $print_fail->store($oversized) },
    qr/Can't\ append\ to\ relay\ store\ file/mx,
    'an append larger than the write buffer croaks at print';
};

# Loading the legacy format leaves the store needing a full rewrite, so the
# next mutation compacts instead of appending.
sub _legacy_store {
  my ($dir, $name, %event_args) = @_;
  my $path  = "$dir/$name";
  my $event = _event(created_at => 1_700_000_100, %event_args);
  open my $fh, '>:raw', $path or die "open $path: $!";
  print {$fh} $JSON->encode([$event->to_hash]) . "\n" or die "write $path: $!";
  close $fh;
  return Overnet::Relay::Store::File->new(path => $path);
}

subtest 'unwritable compaction targets are reported' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $next = _event(content => 'compaction trigger', created_at => 1_700_000_101);

  my $blocked_tmp = _legacy_store($dir, 'blocked-tmp.json', content => 'small');
  mkdir $blocked_tmp->path . '.tmp.' . $$ or die "mkdir: $!";
  like dies { $blocked_tmp->store($next) },
    qr/Can't\ open\ relay\ store\ temp\ file .* for\ writing/mx,
    'an unopenable temp file croaks the compaction';

  my $rename_fail = _legacy_store($dir, 'rename-fail.json', content => 'small');
  mkdir "$dir/rename-target" or die "mkdir: $!";
  $rename_fail->path("$dir/rename-target");
  like dies { $rename_fail->store($next) },
    qr/Can't\ rename\ relay\ store\ temp\ file/mx,
    'a store path that cannot be replaced croaks at rename';
};

subtest 'compaction write failures are reported' => sub {
  skip_all 'no writable /dev/full fault-injection device'
    if !(-c '/dev/full' && -w '/dev/full');

  my $dir  = tempdir(CLEANUP => 1);
  my $next = _event(content => 'compaction trigger', created_at => 1_700_000_102);

  my $close_fail = _legacy_store($dir, 'close-fail.json', content => 'small');
  symlink '/dev/full', $close_fail->path . '.tmp.' . $$ or die "symlink: $!";
  like dies { $close_fail->store($next) },
    qr/Can't\ close\ relay\ store\ temp\ file/mx,
    'a small compaction croaks when the flush at close fails';

  my $print_fail = _legacy_store($dir, 'print-fail.json', content => 'y' x 70_000);
  symlink '/dev/full', $print_fail->path . '.tmp.' . $$ or die "symlink: $!";
  like dies { $print_fail->store($next) },
    qr/Can't\ write\ relay\ store\ temp\ file/mx,
    'an oversized compaction croaks at print';
};

subtest 'missing store directories are created on first write' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = "$dir/nested/deeper/store.json";
  my $store = Overnet::Relay::Store::File->new(path => $path);

  my $event = _event(content => 'nested', created_at => 1_700_000_110);
  $store->store($event);
  ok -f $path, 'the store file lands in the created directory';
  is _ids(Overnet::Relay::Store::File->new(path => $path)), [$event->id],
    'the nested store reloads';
};

done_testing;
