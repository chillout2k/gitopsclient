package gitopsclient

import "github.com/go-resty/resty/v2"

type InstanceOrder struct {
	Instance_name string `json:"instance_name"`
	Orderer_id    string `json:"orderer_id"`
	Bits_account  uint64 `json:"bits_account"`
	Service_id    uint64 `json:"service_id"`
	Replica_count uint64 `json:"replica_count"`
	Version       string `json:"version"`
	Some_value    string `json:"some_value"`
}

type Instance struct {
	Instance_id   string `json:"instance_id"`
	Order_time    string `json:"order_time"`
	Stage         string `json:"stage"`
	Instance_name string `json:"instance_name"`
	Orderer_id    string `json:"orderer_id"`
	Bits_account  uint64 `json:"bits_account"`
	Service_id    uint64 `json:"service_id"`
	Replica_count uint64 `json:"replica_count"`
	Version       string `json:"version"`
	Some_value    string `json:"some_value"`
}

type InstanceUpdate struct {
	Instance_name string `json:"instance_name"`
	Bits_account  uint64 `json:"bits_account"`
	Service_id    uint64 `json:"service_id"`
	Replica_count uint64 `json:"replica_count"`
	Version       string `json:"version"`
	Some_value    string `json:"some_value"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type GitopsClient struct {
	GitopsApiURI        string
	RestyClient         *resty.Client
	CachePath           string
	JwksURI             string
	TokenURI            string
	GrantType           string
	ClientId            string
	ClientSecret        string
	Scopes              string
	Username            string
	Password            string
	AuthURI             string
	RedirectURI         string
	AuthzListenerSocket string
	AccessToken         string
	RefreshToken        string
	Debug               bool
}

type GitopsClientConfig struct {
	GitopsApiURI        string
	CachePath           string
	JwksURI             string
	TokenURI            string
	GrantType           string
	ClientId            string
	ClientSecret        string
	Scopes              string
	Username            string
	Password            string
	AuthURI             string
	RedirectURI         string
	AuthzListenerSocket string
	Debug               bool
}
