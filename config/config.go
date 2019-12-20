package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
)

var (
	configReloadSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_successful",
		Help:      "Blackbox exporter config loaded successfully.",
	})

	configReloadSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "blackbox_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})
)

func init() {
	prometheus.MustRegister(configReloadSuccess)
	prometheus.MustRegister(configReloadSeconds)
}

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

func (sc *SafeConfig) ReloadConfig(confFile string) (err error) {
	var c = &Config{}
	defer func() {
		if err != nil {
			configReloadSuccess.Set(0)
		} else {
			configReloadSuccess.Set(1)
			configReloadSeconds.SetToCurrentTime()
		}
	}()

	yamlFile, err := ioutil.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}

	if err := yaml.UnmarshalStrict(yamlFile, c); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty" toml:"prober"`
	Timeout time.Duration `yaml:"timeout,omitempty" toml:"timeout"`
	HTTP    HTTPProbe     `yaml:"http,omitempty" toml:"http"`
	TCP     TCPProbe      `yaml:"tcp,omitempty" toml:"tcp"`
	ICMP    ICMPProbe     `yaml:"icmp,omitempty" toml:"icmp"`
	DNS     DNSProbe      `yaml:"dns,omitempty" toml:"dns"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                   `yaml:"valid_status_codes,omitempty" toml:"valid_status_codes"`
	ValidHTTPVersions      []string                `yaml:"valid_http_versions,omitempty" toml:"valid_http_versions"`
	IPProtocol             string                  `yaml:"preferred_ip_protocol,omitempty" toml:"preferred_ip_protocol"`
	IPProtocolFallback     bool                    `yaml:"ip_protocol_fallback,omitempty" toml:"ip_protocol_fallback"`
	NoFollowRedirects      bool                    `yaml:"no_follow_redirects,omitempty" toml:"no_follow_redirects"`
	FailIfSSL              bool                    `yaml:"fail_if_ssl,omitempty" toml:"fail_if_ssl"`
	FailIfNotSSL           bool                    `yaml:"fail_if_not_ssl,omitempty" toml:"fail_if_not_ssl"`
	Method                 string                  `yaml:"method,omitempty" toml:"method"`
	Headers                map[string]string       `yaml:"headers,omitempty" toml:"headers"`
	FailIfMatchesRegexp    []string                `yaml:"fail_if_matches_regexp,omitempty" toml:"fail_if_matches_regexp"`
	FailIfNotMatchesRegexp []string                `yaml:"fail_if_not_matches_regexp,omitempty" toml:"fail_if_not_matches_regexp"`
	Body                   string                  `yaml:"body,omitempty" toml:"body"`
	HTTPClientConfig       config.HTTPClientConfig `yaml:"http_client_config,inline" toml:"http_client_config"`
}

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty" toml:"expect"`
	Send     string `yaml:"send,omitempty" toml:"send"`
	StartTLS bool   `yaml:"starttls,omitempty" toml:"starttls"`
}

type TCPProbe struct {
	IPProtocol         string           `yaml:"preferred_ip_protocol,omitempty" toml:"preferred_ip_protocol"`
	IPProtocolFallback bool             `yaml:"ip_protocol_fallback,omitempty" toml:"ip_protocol_fallback"`
	SourceIPAddress    string           `yaml:"source_ip_address,omitempty" toml:"source_ip_address"`
	QueryResponse      []QueryResponse  `yaml:"query_response,omitempty" toml:"query_response"`
	TLS                bool             `yaml:"tls,omitempty" toml:"tls"`
	TLSConfig          config.TLSConfig `yaml:"tls_config,omitempty" toml:"tls_config"`
}

type ICMPProbe struct {
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty" toml:"preferred_ip_protocol"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty" toml:"ip_protocol_fallback"`
	SourceIPAddress    string `yaml:"source_ip_address,omitempty" toml:"source_ip_address"`
	PayloadSize        int    `yaml:"payload_size,omitempty" toml:"payload_size"`
	DontFragment       bool   `yaml:"dont_fragment,omitempty" toml:"dont_fragment"`
}

type DNSProbe struct {
	IPProtocol         string         `yaml:"preferred_ip_protocol,omitempty" toml:"preferred_ip_protocol"`
	IPProtocolFallback bool           `yaml:"ip_protocol_fallback,omitempty" toml:"ip_protocol_fallback"`
	SourceIPAddress    string         `yaml:"source_ip_address,omitempty" toml:"source_ip_address"`
	TransportProtocol  string         `yaml:"transport_protocol,omitempty" toml:"transport_protocol"`
	QueryName          string         `yaml:"query_name,omitempty" toml:"query_name"`
	QueryType          string         `yaml:"query_type,omitempty" toml:"query_type"`   // Defaults to ANY.
	ValidRcodes        []string       `yaml:"valid_rcodes,omitempty" toml:"valid_rcodes"` // Defaults to NOERROR.
	ValidateAnswer     DNSRRValidator `yaml:"validate_answer_rrs,omitempty" toml:"validate_answer_rrs"`
	ValidateAuthority  DNSRRValidator `yaml:"validate_authority_rrs,omitempty" toml:"validate_authority_rrs"`
	ValidateAdditional DNSRRValidator `yaml:"validate_additional_rrs,omitempty" toml:"validate_additional_rss"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp,omitempty" toml:"fail_if_matches_regex"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp,omitempty" toml:"fail_if_not_matches_regexp"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := s.HTTPClientConfig.Validate(); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if s.QueryName == "" {
		return errors.New("query name must be set for DNS module")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain TCPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSRRValidator) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSRRValidator
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *ICMPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if runtime.GOOS == "windows" && s.DontFragment {
		return errors.New("\"dont_fragment\" is not supported on windows platforms")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *QueryResponse) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain QueryResponse
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}
