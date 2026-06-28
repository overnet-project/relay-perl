use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3;
use Symbol qw(gensym);
use Test::More;

my $relay_script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-relay.pl');

subtest 'relay help exposes profile contract controls' => sub {
  my $result = _run($^X, $relay_script, '--help');

  is $result->{exit}, 0, 'help exits successfully';
  like $result->{stdout}, qr/--profile-contract\b/,
    'help exposes profile contract file option';
  like $result->{stdout}, qr/--profile-contract-policy\b/,
    'help exposes profile contract policy option';
};

subtest 'relay validates profile contract CLI inputs before listening' => sub {
  my $tempdir = tempdir(CLEANUP => 1);
  my $missing_path = File::Spec->catfile($tempdir, 'missing.json');

  my $missing = _run(
    $^X, $relay_script,
    '--host', '127.0.0.1',
    '--port', '0',
    '--profile-contract', $missing_path,
  );
  isnt $missing->{exit}, 0, 'missing profile contract file fails';
  like $missing->{stderr}, qr/profile contract file .*: No such file or directory/,
    'missing file failure is explicit';

  my $invalid_json_path = File::Spec->catfile($tempdir, 'invalid-json.json');
  _write_file($invalid_json_path, '{');
  my $invalid_json = _run(
    $^X, $relay_script,
    '--host', '127.0.0.1',
    '--port', '0',
    '--profile-contract', $invalid_json_path,
  );
  isnt $invalid_json->{exit}, 0, 'invalid profile contract JSON fails';
  like $invalid_json->{stderr}, qr/invalid profile contract JSON/,
    'invalid JSON failure is explicit';

  my $not_object_path = File::Spec->catfile($tempdir, 'array.json');
  _write_file($not_object_path, '[]');
  my $not_object = _run(
    $^X, $relay_script,
    '--host', '127.0.0.1',
    '--port', '0',
    '--profile-contract', $not_object_path,
  );
  isnt $not_object->{exit}, 0, 'non-object profile contract fails';
  like $not_object->{stderr}, qr/profile contract file .* must contain a JSON object/,
    'non-object failure is explicit';

  my $invalid_contract_path = File::Spec->catfile($tempdir, 'invalid-contract.json');
  _write_file($invalid_contract_path, '{}');
  my $invalid_contract = _run(
    $^X, $relay_script,
    '--host', '127.0.0.1',
    '--port', '0',
    '--profile-contract-policy', 'known',
    '--profile-contract', $invalid_contract_path,
  );
  isnt $invalid_contract->{exit}, 0, 'structurally invalid contract fails';
  like $invalid_contract->{stderr}, qr/invalid profile_contracts: profile_contract\./,
    'contract validation failure is explicit';

  my $invalid_policy = _run(
    $^X, $relay_script,
    '--host', '127.0.0.1',
    '--port', '0',
    '--profile-contract-policy', 'strict',
  );
  isnt $invalid_policy->{exit}, 0, 'invalid profile contract policy fails';
  like $invalid_policy->{stderr}, qr/profile_contract_policy must be off, known, or required/,
    'invalid policy failure is explicit';
};

done_testing;

sub _write_file {
  my ($path, $content) = @_;
  open my $fh, '>:raw', $path
    or die "Can't write $path: $!";
  print {$fh} $content
    or die "Can't write $path: $!";
  close $fh
    or die "Can't close $path: $!";
}

sub _run {
  my (@cmd) = @_;
  my $stderr = gensym;
  my $pid = open3(my $stdin, my $stdout, $stderr, @cmd);
  close $stdin;
  my $stdout_text = do { local $/; <$stdout> // '' };
  my $stderr_text = do { local $/; <$stderr> // '' };
  waitpid $pid, 0;
  return {
    exit => $? >> 8,
    stdout => $stdout_text,
    stderr => $stderr_text,
  };
}
