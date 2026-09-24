# Rename `ext_traefik-middleware-utilities_packages` to a leaf that names the object

IssueKey: 2026-09-24-adopt-utilities-v1-0-7
Size: large
Action: note

## Why this follow-up
Domain index heading `Packages layout and APIs` and last slug part `packages` do not name an object (reclaim table, SimpleRedis, or a pin).

## Why it was not taken
This run did not create the folder. Unattended take is only small rows on files this run created. New v1.0.7 facts landed under precise slugs instead.

## Risks
Later agents keep folding pin and API notes into the grab-bag folder.

## Context
Current: `knowledge/research/ext_traefik-middleware-utilities_packages/`
This run added: `ext_traefik-middleware-utilities_traefikemulator/`, `ext_traefik-middleware-utilities_reclaim_alias/`
