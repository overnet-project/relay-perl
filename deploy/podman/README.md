# Overnet relay — podman deployment

This directory packages the generic Overnet relay as a container image and a
pair of [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
units so it can be run and supervised as a rootless `systemd --user` service.

It deploys the **generic relay** — the `overnet-relay-service.pl` entrypoint
in `bin/`, the same one driven by `deploy/systemd/overnet-relay.service`. It
serves the Overnet relay protocol (publish, query, subscribe, sync, object
read) with a persistent on-disk event store. Hosting authoritative NIP-29
channels is a separate role (its launcher currently lives in the `irc-server`
repository) and is **not** built by this image.

## Contents

| File | Purpose |
| --- | --- |
| `Containerfile` | Builds the relay image from sibling `core-perl/` + `relay-perl/` checkouts. |
| `overnet-relay.container` | Quadlet unit that runs the relay as a `systemd --user` service. |
| `overnet-relay.volume` | Quadlet unit declaring the named volume for the event store. |

## Why podman + Quadlet

The relay is a long-lived network service that must survive restarts and keep
a persistent store. Quadlet lets podman describe the container declaratively
and hands supervision (restart, ordering, health) to systemd, with no daemon
and no root. Everything below runs as an ordinary user.

## Prerequisites

- `podman` 4.4+ (Quadlet support) with the `systemd --user` session usable.
  For a login-independent service, enable lingering: `loginctl enable-linger`.
- A workspace containing sibling `core-perl/` and `relay-perl/` checkouts.
  Overnet core is used from its source tree (it is not on CPAN), so both
  repositories must be present in the build context.

## Build the image

Run from the workspace directory that holds both checkouts:

```bash
podman build \
  --file relay-perl/deploy/podman/Containerfile \
  --tag overnet-relay:latest \
  .
```

The build installs the core and relay CPAN prerequisites, then copies both
source trees to `/opt/overnet`. The relay resolves core at
`/opt/overnet/core-perl/lib` via the entrypoint's `use lib` fallback, so the
sibling layout inside the image mirrors the development layout.

## Install and start the service (rootless)

```bash
mkdir -p ~/.config/containers/systemd
cp relay-perl/deploy/podman/overnet-relay.container \
   relay-perl/deploy/podman/overnet-relay.volume \
   ~/.config/containers/systemd/

systemctl --user daemon-reload
systemctl --user start overnet-relay
```

Quadlet generates a transient `overnet-relay.service` from the `.container`
file. Manage it like any user service:

```bash
systemctl --user status overnet-relay
journalctl --user -u overnet-relay -f
```

## Verify

The relay writes readiness transitions to its log and maintains a health file
inside the store volume:

```bash
# Readiness and other lifecycle lines are logged to the journal:
journalctl --user -u overnet-relay | grep '\[relay.health\]'

# The health file reports ready/stopping/stopped with the listen address:
podman exec overnet-relay cat /var/lib/overnet/relay/health.json
```

The Quadlet unit also defines a podman health check that opens a TCP
connection to the listener; `podman healthcheck run overnet-relay` runs it on
demand.

## Configuration

Tuning knobs are the `overnet-relay-service.pl` arguments on the unit's
`Exec=` line. Edit them in place, then reload:

```bash
$EDITOR ~/.config/containers/systemd/overnet-relay.container
systemctl --user daemon-reload
systemctl --user restart overnet-relay
```

Commonly adjusted arguments:

| Argument | Meaning |
| --- | --- |
| `--relay-profile` | Relay capability profile (default `volunteer-basic`). |
| `--max-connections-per-ip` | Per-IP connection cap. |
| `--event-rate-limit` | Publish rate limit as `COUNT/SECONDS`. |
| `--service-policy NAME=VALUE` | Per-operation access policy (`publish`, `query`, `subscribe`, `sync`, `object_read`). |
| `--store-file` | Store path; must stay inside the mounted volume. |

Run `podman run --rm overnet-relay:latest --help` for the full argument list.

## Persistence

The event store lives in the `overnet-relay-store` named volume, mounted at
`/var/lib/overnet/relay`. The store file is append-structured JSON lines and
survives container restarts, rebuilds, and image updates. To inspect or back
it up:

```bash
podman volume inspect overnet-relay-store
```

The `overnet-relay-backup.pl` and `overnet-relay-sync.pl` tools in `bin/`
operate on this store for backups and relay-to-relay replication.

## Public exposure

`PublishPort` defaults to `127.0.0.1:7447:7447`, so the relay is reachable
only from the host. For a public relay, terminate TLS in a reverse proxy in
front of the loopback listener (recommended), or change `PublishPort` to bind
a public address directly. Overnet relays speak `ws://`; public deployments
should be fronted as `wss://`.

## Updating

Rebuild the image and restart:

```bash
podman build --file relay-perl/deploy/podman/Containerfile --tag overnet-relay:latest .
systemctl --user restart overnet-relay
```

The store volume is independent of the image, so data is retained across
rebuilds.
