# Security

1. [judgement] Client-controlled trust — `pkg/httprule/action.go:117` — a `bypassCaptcha` row with a `path` applies on a path with more than one reading, so a client under a captcha can send `/api/..%2Fadmin` and, on a backend that decodes and resolves it, reach `/admin` without the captcha
   Fix: Read the token after the single-reading check, as the leg skips are
   Status: skipped
   Argument: requester decision recorded on requirement.md Desired and explore.md; only a captcha is weakened, bans are not; measured on Traefik v3.7.11 and v3.7.19 and stated in the README with the entry point options that reject those paths.
2. [judgement] Client-controlled trust — `README.md:569` — a `bypassCaptcha` rule on a header or cookie the client sets lets any visitor skip the captcha on every page, and the section did not say so
   Fix: Say in the README to match on path, host or method, not on a client-set header or cookie
   Status: done
   Argument: sentence added to "Keep captchas off API routes".
