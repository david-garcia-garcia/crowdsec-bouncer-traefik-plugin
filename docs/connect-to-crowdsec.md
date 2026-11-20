[Documentation](README.md) › Connect to CrowdSec

# Connect to CrowdSec

How the plugin authenticates to LAPI and AppSec, and how to encrypt those connections. The settings are listed in [Configuration › LAPI](configuration.md#lapi) and [Configuration › AppSec](configuration.md#appsec).

You can authenticate to LAPI either with `lapiKey` or with client certificates. Both options are described below.

## Generate a LAPI key

Generate a bouncer API key for LAPI, as described in the [CrowdSec documentation](https://docs.crowdsec.net/docs/user_guides/lapi_mgmt):

```bash
docker compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli bouncers add crowdsecBouncer
```

Set this key where `FIXME-LAPI-KEY` appears in `docker-compose.yml`:

```yaml
..
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiEnabled=true"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiKey=FIXME-LAPI-KEY"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiScheme=http"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiHost=crowdsec:8080"
..
crowdsec:
  environment:
    BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY
```

> CrowdSec accepts any string as a key, so `FIXME-LAPI-KEY` would work, but use a long random value in practice.

Then start all the containers:

```bash
docker compose up -d
```

To keep the key out of the configuration, use `lapiKeyFile` (see [Read a value from a file](configuration.md#read-a-value-from-a-file)).

## Use certificates to authenticate with CrowdSec

See [examples/tls-auth](../examples/tls-auth/README.md) for client-certificate authentication with LAPI. In that case, LAPI must be reached over HTTPS.

The script `examples/tls-auth/gencerts.sh` generates the certificates; run it from the directory that holds the PKI input files.

## Use HTTPS to communicate with LAPI

Set `lapiScheme` to `https`. The plugin then verifies CrowdSec's server certificate in one of three ways:

- **Publicly trusted certificate** (e.g. Let's Encrypt behind a reverse proxy): leave `lapiTlsCertificateAuthority` empty and `lapiTlsInsecureVerify` `false`. The system trust store is used (the `traefik` image ships `ca-certificates`).
- **Private or self-signed CA**: set `lapiTlsCertificateAuthority` (or `lapiTlsCertificateAuthorityFile`) to the PEM CA that signed CrowdSec's certificate.
- **No verification** (not for production): set `lapiTlsInsecureVerify` to `true`.

CrowdSec must be listening on HTTPS. See the [tls-auth example](../examples/tls-auth/README.md) or the [CrowdSec documentation](https://docs.crowdsec.net/docs/local_api/tls_auth/).

## Use HTTPS to communicate with AppSec

Set `appsecScheme` to `https` (if left empty, it follows `lapiScheme`). AppSec uses its own `appsecTls…` settings, with the same three options as LAPI: system trust store, a private CA in `appsecTlsCertificateAuthority`, or `appsecTlsInsecureVerify: true`.

To present a client certificate, set `appsecTlsClientCertificate` and `appsecTlsClientKey` (or their `File` variants). CrowdSec must be configured to accept it.
