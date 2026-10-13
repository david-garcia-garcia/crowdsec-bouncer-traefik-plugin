# Nitpicks

1. [hard] Name for the scope — `pkg/configuration/configuration.go:513` — `certBouncer` / `certBouncerKey` still use the old `TLSCertificateBouncer` stem after this body now loads `LapiTLSClientCertificate` / `LapiTLSClientKey`
   Quote:
      ```
      lapiKey, err := GetVariable(config, "LapiKey")
      if err != nil {
      	return err
      }
      certBouncer, err := GetVariable(config, "LapiTLSClientCertificate")
      if err != nil {
      	return err
      }
      certBouncerKey, err := GetVariable(config, "LapiTLSClientKey")
      if err != nil {
      	return err
      }

      if lapiKey == "" && (certBouncer == "" || certBouncerKey == "") {
      	return errors.New("LapiKey || (LapiTLSClientCertificate && LapiTLSClientKey): cannot be all empty")
      }
      if lapiKey != "" && (certBouncer == "" || certBouncerKey == "") {
      	lapiKey = strings.TrimSpace(lapiKey)
      	if err = validateParamsAPIKey(lapiKey, "LapiKey"); err != nil {
      		return err
      	}
      }
      ```
   Fix: Rename to `clientCertificate` / `clientKey` — the role this body uses
   Status: done
   Argument: `validateLapiURLAndKeys` locals are now `clientCertificate` / `clientKey`.
2. [hard] Name for the scope — `pkg/configuration/configuration.go:786` — `certBouncer` / `certBouncerKey` load `TLSClientCertificate` / `TLSClientKey` then become `clientCert`; leftover producer stem plus a second name for the same wrap
   Quote:
      ```
      certBouncer, err := GetVariable(config, prefix+"TLSClientCertificate")
      if err != nil {
      	return nil, err
      }
      certBouncerKey, err := GetVariable(config, prefix+"TLSClientKey")
      if err != nil {
      	return nil, err
      }
      if certBouncer == "" || certBouncerKey == "" {
      	return tlsConfig, nil
      }
      clientCert, err := tls.X509KeyPair([]byte(certBouncer), []byte(certBouncerKey))
      if err != nil {
      	return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
      }
      tlsConfig.Certificates = append(tlsConfig.Certificates, clientCert)
      ```
   Fix: Name the PEMs `clientCertificate` / `clientKey`; keep that stem on the `X509KeyPair` result (`clientCertificatePair`)
   Status: done
   Argument: `getTLSConfig` PEMs and `X509KeyPair` result now use `clientCertificate` / `clientKey` / `clientCertificatePair`.
