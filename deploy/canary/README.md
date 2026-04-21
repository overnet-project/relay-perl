# Overnet Canary Relay Topology

This canary topology runs two relays and one IRC server.

- `relay-a` is the primary authoritative relay.
- `relay-b` is the secondary relay and recovery target.
- relay sync runs in both directions so one relay can die and catch up after restart.

Each service writes a health file for systemd or external checks. Use persisted store paths for both relays, keep sync configs under `/etc/overnet`, and point the IRC server at the primary authority relay URL.
