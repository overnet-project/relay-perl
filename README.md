# Overnet Relay Perl

Perl reference implementation workspace for the Overnet relay, relay sync, deploy wrappers, and relay-backed IRC integration gate.

This repo depends on the sibling `../overnet-core-perl/` workspace for shared core, authority, and program runtime modules.

## Scope

This repo owns:

- `Overnet::Relay` and the relay module tree
- relay persistence, backup, and sync CLIs
- authoritative relay helpers
- relay deploy packaging and canary topology assets
- relay-backed IRC integration and release-gate tests

Shared core validation and runtime code live in `../overnet-core-perl/`.

## Tests

Run the full relay-heavy verification path with:

```bash
/home/_73/.local/bin/plx prove \
  -Ilib \
  -Ilocal/lib/perl5 \
  -I../overnet-core-perl/lib \
  -I../overnet-core-perl/local/lib/perl5 \
  -r t
```

The default release gate is `bin/overnet-release-gate.pl`.

It runs the IRC verification path:

- `t/spec-conformance-irc-server.t`
- `t/program-irc-server.t`
- `t/program-irc-server-relay.t`
- `t/program-irc-server-relay-fault.t`
- `t/program-irc-server-relay-failover.t`
- `t/relay-live.t`
- `t/relay-sync-live.t`
- `t/deploy-restore-drill-live.t`

Run the default release gate with:

```bash
/home/_73/.local/bin/plx perl -Ilib -Ilocal/lib/perl5 bin/overnet-release-gate.pl
```
