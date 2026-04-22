# Overnet Relay Perl — Project Instructions

This directory contains the Perl reference implementation for the Overnet relay and relay-backed integration surface.

The specification in `../spec/` is authoritative. Shared core/runtime semantics live in `../core-perl/`. Relay behavior, deploy packaging, and the heavy IRC gate live here.

## Priorities

When rules conflict, follow this order:

1. Overnet spec correctness
2. Preserving documented relay/runtime behavior unless intentionally changing it
3. Tests and release-gate coverage
4. Deploy and recovery correctness
5. Local style rules

## Testing

Use the sibling core repo on `@INC` when running tests here:

```bash
/home/_73/.local/bin/plx prove \
  -Ilib \
  -Ilocal/lib/perl5 \
  -I../core-perl/lib \
  -I../core-perl/local/lib/perl5 \
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

After making changes, always run the relevant live slices and the release gate when they are in scope.
