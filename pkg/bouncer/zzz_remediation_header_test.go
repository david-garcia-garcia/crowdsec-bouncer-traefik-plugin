package bouncer

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

func TestFormatRemediationHeader(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		reason string
		origin string
		want   string
	}{
		{name: "empty origin omits third field", kind: headerKindBan, reason: headerReasonLAPI, origin: "", want: "ban:lapi"},
		{name: "crowdsec origin", kind: headerKindBan, reason: headerReasonLAPI, origin: "crowdsec", want: "ban:lapi:crowdsec"},
		{name: "lists prefix becomes lists_", kind: headerKindBan, reason: headerReasonLAPI, origin: "lists:firehol_level1", want: "ban:lapi:lists_firehol_level1"},
		{name: "CR LF TAB stripped from origin", kind: headerKindBan, reason: headerReasonLAPI, origin: "crowd\rsec\n:\tkeep", want: "ban:lapi:crowdsec:keep"},
		{name: "leftover colon in non-lists origin stays", kind: headerKindBan, reason: headerReasonLAPI, origin: "custom:origin", want: "ban:lapi:custom:origin"},
		{name: "closed reason never takes origin", kind: headerKindBan, reason: headerReasonCacheFail, origin: "plugin:tech_cachefail", want: "ban:cache-fail"},
		{name: "empty kind does not invent allow pass", kind: "", reason: headerReasonLAPI, origin: "crowdsec", want: ""},
		{name: "empty reason does not invent allow pass", kind: headerKindBan, reason: "", origin: "crowdsec", want: ""},
		{name: "disconnect exact", kind: headerKindError, reason: headerReasonClientDisconnected, origin: "", want: "error:client-disconnected"},
		{name: "captcha lapi origin", kind: headerKindCaptcha, reason: headerReasonLAPI, origin: "cscli", want: "captcha:lapi:cscli"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRemediationHeader(tt.kind, tt.reason, tt.origin)
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestHeaderReasonFromOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   string
	}{
		{origin: lapi.OriginPluginForcedDecision, want: headerReasonDecisionHeader},
		{origin: lapi.OriginPluginLapiFailure, want: headerReasonLAPIFailure},
		{origin: lapi.OriginPluginTechStreamFail, want: headerReasonStreamUnhealthy},
		{origin: lapi.OriginPluginAppsecFailure, want: headerReasonAppsecFailure},
		{origin: "crowdsec", want: headerReasonLAPI},
		{origin: "lists:firehol_level1", want: headerReasonLAPI},
		{origin: "", want: headerReasonLAPI},
	}
	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			got := headerReasonFromOrigin(tt.origin)
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestFormatAppsecRelayHeader(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   string
	}{
		{name: "captcha", action: "captcha", want: "captcha:appsec"},
		{name: "challenge", action: "challenge", want: "captcha:challenge"},
		{name: "unknown colon becomes underscore", action: "foo:bar", want: "foo_bar:appsec"},
		{name: "unknown trimmed and ctl stripped", action: "  foo\r:\nbar\t  ", want: "foo_bar:appsec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAppsecRelayHeader(tt.action)
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}
