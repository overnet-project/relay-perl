# Overnet Relay Perl

Perl reference implementation workspace for the Overnet relay, relay sync, deploy wrappers, and relay-backed IRC integration gate.

GitHub: <https://github.com/overnet-project/relay-perl>

This repo depends on [core-perl](https://github.com/overnet-project/core-perl) for shared core, authority, and program runtime modules.

## Scope

This repo owns:

- `Overnet::Relay` and the relay module tree
- relay persistence, backup, and sync CLIs
- authoritative relay helpers
- relay deploy packaging and canary topology assets
- relay-backed IRC integration and release-gate tests

Shared core validation and runtime code live in [core-perl](https://github.com/overnet-project/core-perl).

## Tests

Run the full relay-heavy verification path with:

```bash
prove -r t
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
perl bin/overnet-release-gate.pl
```

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/core-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)
- [irc-server](https://github.com/overnet-project/irc-server)
