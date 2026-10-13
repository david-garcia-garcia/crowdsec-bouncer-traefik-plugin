# Deviations

- CI Yaegi checkout uses go.mod module path `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` instead of `${{ github.repository }}`, and vendor packages are copied onto GOPATH/src. Dest `main` already failed this check on the fork; the ticket requires CI success. Not a copy of upstream PR 403.
