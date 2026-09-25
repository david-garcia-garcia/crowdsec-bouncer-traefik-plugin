package httprule

// Rule is one authoring exemption: omitted fields mean any; set fields AND.
type Rule struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}
