# Overnet Relay Perl — Project Instructions

This repository contains the Perl reference implementation for the Overnet relay, relay sync, deploy tooling, and relay-backed integration surface.

The [Overnet specification](https://github.com/overnet-project/spec) is authoritative. Relay behavior must conform to the [relay specification](https://github.com/overnet-project/spec/blob/main/docs/relay.md), the [core specification](https://github.com/overnet-project/spec/blob/main/docs/core.md), and any applicable profile specifications such as the [IRC adapter specification](https://github.com/overnet-project/spec/blob/main/docs/adapters/irc.md). If implementation behavior and the spec disagree, fix the implementation unless the spec is explicitly changed first.

Shared core validation, authority helpers, and program runtime semantics live in the [core Perl repository](https://github.com/overnet-project/core-perl). IRC-specific adapter and server behavior lives in the [IRC adapter](https://github.com/overnet-project/adapter-irc-perl) and [IRC server](https://github.com/overnet-project/irc-server) repositories.

## Priorities

When rules conflict, follow this order:

1. Overnet spec correctness
2. Preserving documented relay/runtime behavior unless intentionally changing it
3. Tests and release-gate coverage
4. Deploy and recovery correctness
5. Local style rules

If relay work exposes a spec ambiguity or gap, update the spec and any relevant fixtures first, then update this implementation.

## Scope

This repository owns:

- `Overnet::Relay` and the relay module tree
- relay storage, backup, and sync behavior
- relay command-line tools and service wrappers
- relay deploy packaging and canary topology assets
- relay-backed integration tests, including IRC release-gate coverage

This repository does not own shared core validation or IRC mapping semantics. Do not copy or fork those rules here when they belong in the spec, [core Perl](https://github.com/overnet-project/core-perl), [IRC adapter](https://github.com/overnet-project/adapter-irc-perl), or [IRC server](https://github.com/overnet-project/irc-server) repositories.

## Spec-First Workflow

For behavior changes that affect protocol, relay, sync, deploy, or relay-backed integration semantics:

1. Identify the normative spec section or fixture that defines the expected behavior.
2. Update or clarify the spec if the expected behavior is not already specified.
3. Add or update conformance fixtures when the behavior is fixture-testable.
4. Add or update the relevant relay tests.
5. Run the test and confirm the new case fails for the expected reason.
6. Implement the change until the relevant tests pass.
7. Re-run the relevant release-gate slice before considering the work done.

Do not let this relay implementation become the de facto spec.

## Testing

Follow TDD strictly. Add or update tests before implementing behavior changes, and run the smallest relevant test slice first.

The default relay-backed release gate is:

```bash
perl bin/overnet-release-gate.pl
```

It runs:

- `t/spec-conformance-irc-server.t`
- `t/program-irc-server.t`
- `t/program-irc-server-relay.t`
- `t/program-irc-server-relay-fault.t`
- `t/program-irc-server-relay-failover.t`
- `t/relay-live.t`
- `t/relay-sync-live.t`
- `t/deploy-restore-drill-live.t`

Run broader live slices when a change affects relay startup, WebSocket behavior, persistence, relay sync, backup/restore, deploy packaging, IRC relay integration, or recovery behavior.

Live tests may start local services, bind ports, create temporary stores, and exercise process lifecycle behavior. Treat failures in live tests as real integration failures unless you have a concrete environmental cause.

## Relay Behavior

Relay behavior should remain Nostr-native where the spec requires Nostr-native publication, query, subscription, and negentropy behavior. Overnet-specific relay behavior belongs at the protocol boundaries defined by the spec: validation, metadata advertisement, filter support, outcome codes, object-read surfaces, sync, persistence, and advertised operator policy.

Do not weaken validation to make integration tests pass. If a valid scenario appears to require weaker validation, first check whether the spec is missing a rule or whether the test fixture is wrong.

## Deploy And Recovery

Deploy, backup, restore, relay sync, and canary assets are part of the reference implementation surface. Keep them aligned with the same behavior exercised by the live tests.

When changing deploy or recovery behavior, include a test or drill that proves:

- the service starts with documented configuration
- health/readiness signals are meaningful
- persisted relay state survives the intended backup or restore path
- relay sync recovers or converges as expected

## Documentation And Drift Control

The spec is the primary documentation for protocol behavior. Repository documentation should explain how this implementation realizes the spec, not redefine protocol correctness.

When implementation work exposes a mismatch:

1. identify the exact missing, unclear, or contradicted rule
2. update the spec or fixture if needed
3. update relay tests
4. then update the implementation

## Output Requirements

At the end of every task, report:

- files changed
- behavior changes
- validation changes
- deploy/recovery changes
- tests run
- spec sections consulted
- anything not verified
- follow-up risks or edge cases still worth checking

Do not claim completion if relevant live or release-gate tests were not run.
