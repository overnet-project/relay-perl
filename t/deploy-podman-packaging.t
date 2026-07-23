use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $code_root   = File::Spec->catdir($FindBin::Bin, '..');
my $podman_dir  = File::Spec->catdir($code_root, 'deploy', 'podman');
my $containerfile = File::Spec->catfile($podman_dir, 'Containerfile');
my $container_unit = File::Spec->catfile($podman_dir, 'overnet-relay.container');
my $volume_unit    = File::Spec->catfile($podman_dir, 'overnet-relay.volume');
my $readme         = File::Spec->catfile($podman_dir, 'README.md');

ok -f $containerfile,  'Containerfile exists';
ok -f $container_unit, 'Quadlet .container unit exists';
ok -f $volume_unit,    'Quadlet .volume unit exists';
ok -f $readme,         'podman deploy README exists';

my $containerfile_text = _slurp($containerfile);
like $containerfile_text, qr{^FROM\s+\S*perl:}mx,
  'Containerfile builds on a perl base image';
like $containerfile_text, qr{COPY\s+core-perl\b}mx,
  'Containerfile copies the sibling core-perl checkout';
like $containerfile_text, qr{COPY\s+relay-perl\b}mx,
  'Containerfile copies the relay-perl checkout';
like $containerfile_text, qr{PERL5LIB=\S*core-perl/lib}mx,
  'Containerfile exposes core-perl on PERL5LIB before installing deps';
like $containerfile_text, qr{--installdeps\b}mx,
  'Containerfile installs CPAN prerequisites';
like $containerfile_text, qr{overnet-relay-service\.pl}mx,
  'Containerfile entrypoint runs the relay service wrapper';
like $containerfile_text, qr{^USER\s+overnet}mx,
  'Containerfile drops to an unprivileged user';
like $containerfile_text, qr{^EXPOSE\s+7447}mx,
  'Containerfile exposes the relay listener port';

my $container_unit_text = _slurp($container_unit);
like $container_unit_text, qr{^\[Container\]}mx,
  'Quadlet unit declares a [Container] section';
like $container_unit_text, qr{^Image=}mx,
  'Quadlet unit sets an image';
like $container_unit_text, qr{^Volume=overnet-relay-store\.volume:}mx,
  'Quadlet unit mounts the named store volume';
like $container_unit_text, qr{^PublishPort=127\.0\.0\.1:7447:7447}mx,
  'Quadlet unit publishes the listener on loopback by default';
like $container_unit_text, qr{--store-file\s+/var/lib/overnet/relay/store\.json}mx,
  'Quadlet unit points the store file at the mounted volume';
like $container_unit_text, qr{--health-file\s+/var/lib/overnet/relay/health\.json}mx,
  'Quadlet unit configures a health file on the mounted volume';
like $container_unit_text, qr{^HealthCmd=}mx,
  'Quadlet unit defines a health check';

my $volume_unit_text = _slurp($volume_unit);
like $volume_unit_text, qr{^\[Volume\]}mx,
  'Quadlet volume unit declares a [Volume] section';
like $volume_unit_text, qr{^VolumeName=overnet-relay-store}mx,
  'Quadlet volume unit names the store volume';

# The store path baked into the Containerfile CMD, the Quadlet Exec= line, and
# the volume mount must agree, or the store would not persist.
like $containerfile_text, qr{/var/lib/overnet/relay}mx,
  'Containerfile store path matches the mounted volume path';
like $container_unit_text, qr{Volume=overnet-relay-store\.volume:/var/lib/overnet/relay:}mx,
  'Quadlet mount path matches the configured store path';

my $readme_text = _slurp($readme);
like $readme_text, qr{podman\s+build}mx,
  'README documents building the image';
like $readme_text, qr{\.config/containers/systemd}mx,
  'README documents the rootless Quadlet install path';

# Setting VolumeName= makes podman use that name verbatim (no systemd- prefix),
# so the README must inspect the volume by exactly that name and must not refer
# to the prefixed default name the unit does not produce.
my ($volume_name) = $volume_unit_text =~ /^VolumeName=(\S+)/mx;
ok $volume_name, 'volume unit sets an explicit VolumeName';
like $readme_text, qr{podman\s+volume\s+inspect\s+\Q$volume_name\E\b}mx,
  'README inspects the volume by its actual (unprefixed) name';
unlike $readme_text, qr{systemd-\Q$volume_name\E}mx,
  'README does not reference the systemd- prefixed name VolumeName suppresses';

done_testing;
