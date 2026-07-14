use strictures 2;

use Cwd qw(abs_path getcwd);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use Test2::V0;

# Mutation testing with Devel::Mutator. This is the expensive counterpart to the
# coverage gate: coverage asks "did a test execute this line?", mutation asks
# "would a test NOTICE if this line were wrong?". It works by rewriting the
# target modules one small change at a time (== to !=, || to //, and so on) and
# rerunning the suite against each mutant; a mutant that the suite still passes
# is a "survivor" -- code whose behaviour no assertion actually pins down.
#
# It reruns the whole selected suite once per mutant, so it is far too slow for
# a normal author-test pass and is disabled by default. Run it manually, scoped
# to the high-value modules you care about, e.g.:
#
#   OVERNET_MUTATION=1 \
#   OVERNET_MUTATION_FILES=lib/Overnet/Authority/Delegation.pm \
#   OVERNET_MUTATION_TEST_COMMAND='prove -Ilib t/authority-delegation.t' \
#   perl -Ilib xt/author/mutation.t
#
# Knobs (all optional except the two above):
#   OVERNET_MUTATION_FILES          colon/space separated lib/ modules to mutate
#   OVERNET_MUTATION_TEST_COMMAND   suite to run per mutant (default: prove -Ilib t)
#   OVERNET_MUTATION_TIMEOUT        per-mutant seconds before "inconclusive" (default 120)
#   OVERNET_MUTATION_MAX_SURVIVORS  tolerated survivors before failing (default 0)

if (!$ENV{OVERNET_MUTATION}) {
  plan skip_all => 'set OVERNET_MUTATION=1 to run the mutation gate';
}
if (!eval { require Devel::Mutator::Command::Mutate; require Devel::Mutator::Command::Test; require Capture::Tiny; 1 }) {
  plan skip_all => 'Devel::Mutator is not installed (cpanm Devel::Mutator)';
}

my $ROOT = abs_path("$FindBin::Bin/../..");

# An explicit target list is required. Mutating a whole dist would generate
# thousands of mutants and rerun the suite for each, so the operator must name
# the modules under test.
my @targets = grep { length } split /[:\s]+/xms, ($ENV{OVERNET_MUTATION_FILES} // q{});
if (!@targets) {
  plan skip_all => 'set OVERNET_MUTATION_FILES=lib/... (colon- or space-separated) to select modules to mutate';
}
for my $target (@targets) {
  if ($target !~ m{\Alib/}xms || !-f File::Spec->catfile($ROOT, $target)) {
    plan skip_all => "OVERNET_MUTATION_FILES entry is not an existing lib/ file: $target";
  }
}

my $test_command  = $ENV{OVERNET_MUTATION_TEST_COMMAND}  // 'prove -Ilib t';
my $timeout       = $ENV{OVERNET_MUTATION_TIMEOUT}       // 120;
my $max_survivors = $ENV{OVERNET_MUTATION_MAX_SURVIVORS} // 0;

# Devel::Mutator swaps each mutant file over the real one in place while the
# suite runs and moves it back afterwards; if this process were interrupted
# mid-swap the source tree would be left corrupted. So the whole run happens in
# a throwaway copy of the repo. The copy is placed next to the repo (not in the
# system temp dir) so that sibling-relative paths like ../spec and ../core-perl
# still resolve exactly as they do in a real checkout.
my $parent = abs_path(File::Spec->catdir($ROOT, File::Spec->updir));
my $work   = tempdir('overnet-mutation-XXXXXXXX', DIR => $parent, CLEANUP => 1);

# tar out of the repo (excluding VCS and generated dirs) straight into the copy.
my $copy_status =
  system "tar -C '$ROOT' --exclude=.git --exclude=mutants --exclude=cover_db --exclude=blib -cf - . | tar -C '$work' -xf -";
is $copy_status, 0, 'copied the repo into an isolated work tree' or bail_out('could not stage a work tree');

my $cwd = getcwd();
chdir $work or bail_out("chdir $work: $!");

my $mutate_out = Capture::Tiny::capture_merged(sub {
  Devel::Mutator::Command::Mutate->new(root => q{.})->run(@targets);
});
my ($mutant_count) = $mutate_out =~ /mutants:\s*(\d+)/xms;
$mutant_count //= 0;

my $test_out = q{};
if ($mutant_count > 0) {
  $test_out = Capture::Tiny::capture_merged(sub {
    Devel::Mutator::Command::Test->new(root => q{.}, command => $test_command, timeout => $timeout)->run;
  });
}

chdir $cwd or bail_out("chdir $cwd: $!");

my ($survivors) = $test_out =~ /Result:\s*FAIL\s*\((\d+)\//xms;
$survivors //= 0;
my $timeouts = () = $test_out =~ /[.][.][.]\s+n\/a\s+\(timeout/xmsg;

ok $mutant_count > 0, "generated mutants for the target modules ($mutant_count mutants)"
  or diag $mutate_out;

ok $survivors <= $max_survivors,
  "surviving mutants ($survivors) within the allowed maximum ($max_survivors)"
  or diag "Mutations your tests did not catch:\n$test_out";

ok $timeouts == 0, "no inconclusive (timed-out) mutants ($timeouts)"
  or diag "Raise OVERNET_MUTATION_TIMEOUT or narrow OVERNET_MUTATION_TEST_COMMAND; a "
  . 'timed-out mutant is neither killed nor counted as a survivor.';

done_testing;
