package lapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	crowdsecLapiHeader      = "X-Api-Key"
	crowdsecLapiRoute       = "v1/decisions"
	crowdsecLapiStreamRoute = "v1/decisions/stream"
	crowdsecCapiHost        = "api.crowdsec.net"
	crowdsecCapiHeader      = "Authorization"
	crowdsecCapiLoginRoute  = "v2/watchers/login"
	crowdsecCapiStreamRoute = "v2/decisions/stream"
)

// Login is the body returned from Crowdsec Login CAPI.
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

func closeIdle(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	if t, ok := httpClient.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func (c *Client) getToken() error {
	loginURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}
	loginData := []byte(fmt.Sprintf(
		`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
		c.crowdsecMachineID,
		c.crowdsecPassword,
		strings.Join(c.crowdsecScenarios, `","`),
	))
	body, err := c.crowdsecQuery(loginURL.String(), loginData)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("getToken:parsingBody %w", err)
	}
	if login.Code == http.StatusOK && len(login.Token) > 0 {
		c.crowdsecKey = login.Token
		return nil
	}
	c.log.Warn("getToken statusCode:" + strconv.Itoa(login.Code))
	return errors.New("getToken statusCode:" + strconv.Itoa(login.Code))
}

// crowdsecQuery performs one LAPI/CAPI request and returns the response body on 2xx.
func (c *Client) crowdsecQuery(stringURL string, data []byte) ([]byte, error) {
	method := http.MethodGet
	var postBody []byte
	if len(data) > 0 {
		method = http.MethodPost
		postBody = append([]byte(nil), data...)
	}
	return c.crowdsecQueryWithMethod(stringURL, method, postBody)
}

func (c *Client) crowdsecQueryWithMethod(stringURL, method string, postBody []byte) ([]byte, error) {
	var body io.Reader
	if len(postBody) > 0 {
		body = bytes.NewReader(postBody)
	}
	req, err := http.NewRequest(method, stringURL, body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:newRequest url:%s %w", stringURL, err)
	}
	req.Header.Set(c.crowdsecHeader, c.crowdsecKey)
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+c.pluginVersion)

	res, err := c.httpClient.Do(req)
	if err != nil || res == nil {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			c.log.Error("crowdsecQuery:closeBody " + closeErr.Error())
		}
	}()
	if isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s statusCode:%d", stringURL, res.StatusCode)
	}
	if res.StatusCode == http.StatusUnauthorized && c.crowdsecMode == configuration.AloneMode {
		if errToken := c.getToken(); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return c.crowdsecQueryWithMethod(stringURL, method, postBody)
	}

	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("crowdsecQuery method:%s url:%s, statusCode:%d (expected: 2xx)", req.Method, stringURL, res.StatusCode)
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return responseBody, nil
}
