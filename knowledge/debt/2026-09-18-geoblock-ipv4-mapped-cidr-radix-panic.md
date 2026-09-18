# traefik-geoblock iplookup still panics on IPv4-mapped CIDRs

IssueKey: 2026-09-18-ipv4-mapped-cidr-radix-panic
Size: large
Action: note

## Why this follow-up
Upstream `pkg/iplookup` in traefik-geoblock uses the same `To4()` plus walk-`prefixLen`-from-bit-96 insert. `::ffff:0:0/96` panics there too.

## Why it was not taken
This ticket bounds the fix to this plugin. Upstream traefik-geoblock is out of scope.

## Risks
A later copy from geoblock can reintroduce the panic if this tree’s insert is overwritten.

## Context
Owner notes: `knowledge/research/ext_traefik-geoblock_iplookup/notes.md`.
