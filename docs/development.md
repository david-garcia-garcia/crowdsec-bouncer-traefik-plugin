[Documentation](README.md) › Development

# Development

Run the tests and load the plugin from a checkout.

## Testing

Unit tests and lint:

```bash
make test
make lint
```

Mock end-to-end tests (Traefik binary and a mock LAPI, no CrowdSec):

```bash
make e2e_mock
```

Real-stack end-to-end tests (Traefik and CrowdSec in Docker, with Pester):

```bash
./tests/e2e/real/Test-Integration.ps1
# or
make e2e_pester
```

`make test` also checks this documentation: every setting of the plugin must have its own heading in [configuration.md](configuration.md), and every relative link must point to an existing file and heading.

## Local mode

Traefik's local plugin mode loads a plugin from disk instead of the plugin catalog.
The Traefik static configuration declares the module name (see [Declare the plugin](configuration.md#declare-the-plugin)), and the sources go in a `./plugins-local` directory inside the working directory of the Traefik process:

```
./plugins-local/
    └── src
        └── github.com
            └── david-garcia-garcia
                └── crowdsec-bouncer-traefik-plugin
                    ├── plugin.go
                    ├── go.mod
                    ├── LICENSE
                    ├── Makefile
                    ├── README.md
                    └── vendor/*
```

For local development, `docker-compose.local.yml` reproduces this layout. Generate and set your LAPI key first (see [Generate a LAPI key](connect-to-crowdsec.md#generate-a-lapi-key)), then run:

```bash
docker compose -f docker-compose.local.yml up -d
```

Equivalent to

```bash
make run_local
```

## Design notes

- [LAPI modes in detail](modes.md): sequence diagrams for each `lapiMode`.
- [reCAPTCHA Enterprise](recaptcha-enterprise.md): how checkbox and score keys are validated.
- [traefikemulator](traefikemulator.md): the test helper that reproduces Traefik's router construction.
