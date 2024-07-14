package gitopsclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

func (c *GitopsClient) oauth2ResourceOwnerCredentialsFlow(tokResp *tokenResponse) error {
	resp, err := c.RestyClient.R().
		SetFormData(map[string]string{
			"grant_type":    "password",
			"client_id":     c.ClientId,
			"client_secret": c.ClientSecret,
			"username":      c.Username,
			"password":      c.Password,
		}).
		SetResult(&tokResp).
		Post(c.TokenURI)
	if err != nil {
		return err
	}
	err = c.handleResponse(resp)
	return err
}

func (c *GitopsClient) runAuthCodeFlowServer(wg *sync.WaitGroup, tokResp *tokenResponse) {
	authzHandler := func(w http.ResponseWriter, req *http.Request) {
		fmt.Println("Starting authz-listener on http://" + c.AuthzListenerSocket)
		if len(req.URL.Query().Get("error")) > 0 {
			err := req.URL.Query().Get("error")
			io.WriteString(w, "ERROR: "+err)
			fmt.Println("funAuthzListener error:", err)
			wg.Done()
		}
		restyC := resty.New()
		_, err := restyC.R().
			SetFormData(map[string]string{
				"grant_type":    "authorization_code",
				"code":          req.URL.Query().Get("code"),
				"client_id":     c.ClientId,
				"client_secret": c.ClientSecret,
				"redirect_uri":  c.RedirectURI,
			}).
			SetResult(&tokResp).
			Post(c.TokenURI)
		if err != nil {
			fmt.Println("Autentication failed:", err)
			wg.Done()
		}
		io.WriteString(w, "Great, authentication successful!")
		wg.Done()
	}
	http.HandleFunc("/authz", authzHandler)
	fmt.Println(http.ListenAndServe(c.AuthzListenerSocket, nil))
}

func (c *GitopsClient) openBrowser(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		return err
	}
	fmt.Println("If your webbrowser doesn´t come up, browse to the following URL manually:", url)
	return err
}

func (c *GitopsClient) openAuthCodeFlowBrowser(wg *sync.WaitGroup) {
	url := c.AuthURI + "?response_type=code&client_id=" +
		c.ClientId + "&scope=" + c.Scopes + "&redirect_uri=" +
		c.RedirectURI + "&state=xyz&nonce=abc"
	err := c.openBrowser(url)
	if err != nil {
		fmt.Println("openAuthCodeFlowBrowser error:", err)
	}
	wg.Done()
}

func (c *GitopsClient) oauth2AuthorizationCodeFlow(tokResp *tokenResponse) {
	var wg sync.WaitGroup
	wg.Add(2)
	go c.runAuthCodeFlowServer(&wg, tokResp)
	go c.openAuthCodeFlowBrowser(&wg)
	wg.Wait()
}

func (c *GitopsClient) oauth2DeviceCodeFlow(tokResp *tokenResponse) error {
	var devCodeResp deviceCodeResponse
	// 1. get user_code and device_code from IDP
	resp, err := c.RestyClient.R().
		SetFormData(map[string]string{
			"client_id":     c.ClientId,
			"client_secret": c.ClientSecret,
		}).
		SetResult(&devCodeResp).
		Post(c.AuthURI + "/device")
	if err != nil {
		return err
	}
	err = c.handleResponse(resp)
	if err != nil {
		return err
	}
	// 2. authenticate identity via browser
	c.openBrowser(devCodeResp.VerificationURIComplete)
	// 3. poll for tokens
	fmt.Printf(
		"Waiting for end user to authenticate and accept the authorization request (timeout: %v seconds)\n",
		devCodeResp.ExpiresIn,
	)
	for i := 0; i < devCodeResp.ExpiresIn; i += devCodeResp.Interval {
		resp, err := c.RestyClient.R().
			SetFormData(map[string]string{
				"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":     c.ClientId,
				"client_secret": c.ClientSecret,
				"device_code":   devCodeResp.DeviceCode,
			}).
			SetResult(&tokResp).
			Post(c.TokenURI)
		if err != nil {
			return err
		}
		err = c.handleResponse(resp)
		if err != nil {
			type errorResponse struct {
				Error     string `json:"error"`
				ErrorDesc string `json:"error_description"`
			}
			var errResp errorResponse
			json.Unmarshal(resp.Body(), &errResp)
			switch errResp.Error {
			case "authorization_pending":
				// do nothing and wait another interval
			case "access_denied":
				return errors.New(errResp.ErrorDesc)
			}
		} else {
			// Received tokens successfully
			return nil
		}
		time.Sleep(time.Duration(devCodeResp.Interval * int(time.Second)))
	}
	return errors.New("authorization request expired")
}

func (c *GitopsClient) GetToken() error {
	var tokResp tokenResponse
	var err error
	if c.GrantType == "password" {
		err = c.oauth2ResourceOwnerCredentialsFlow(&tokResp)
		if err != nil {
			return err
		}
	} else if c.GrantType == "auth_code" {
		c.oauth2AuthorizationCodeFlow(&tokResp)
	} else if c.GrantType == "device_code" {
		err = c.oauth2DeviceCodeFlow(&tokResp)
		if err != nil {
			return err
		}
	} else {
		return errors.New("unknown GrantType: " + c.GrantType)
	}
	c.AccessToken = tokResp.AccessToken
	err = c.updateTokenCache("access")
	if err != nil {
		return err
	}
	c.RefreshToken = tokResp.RefreshToken
	err = c.updateTokenCache("refresh")
	return err
}

// Update local token (access/refresh) cache file
func (c *GitopsClient) updateTokenCache(tokenType string) error {
	var tokenFilePath string
	var token string
	if tokenType == "access" {
		tokenFilePath = c.CachePath + "/access_token"
		token = c.AccessToken
	} else if tokenType == "refresh" {
		tokenFilePath = c.CachePath + "/refresh_token"
		token = c.RefreshToken
	} else {
		return errors.New("Unknown tokenType: " + tokenType)
	}
	if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
		os.MkdirAll(c.CachePath, 0700)
	}
	f, err := os.Create(tokenFilePath)
	if err != nil {
		return err
	}
	_, err = f.WriteString(token)
	f.Close()
	return err
}

func (c *GitopsClient) ParseToken(tokenString string) (*jwt.Token, error) {
	jwks, err := keyfunc.NewDefault([]string{c.JwksURI})
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		return nil, err
	}
	if c.Debug {
		fmt.Println("YES! Access token is stil valid!")
	}
	return token, nil
}

func (c *GitopsClient) GetTokenFromCache(tokenType string) error {
	var tokenFilePath string
	if tokenType == "access" {
		tokenFilePath = c.CachePath + "/access_token"
	} else if tokenType == "refresh" {
		tokenFilePath = c.CachePath + "/refresh_token"
	} else {
		return errors.New("Unknown tokenType: " + tokenType)
	}
	tokenBytes, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return err
	}
	if len(tokenBytes) == 0 {
		return errors.New(
			tokenType + " token not found in cache - please login first",
		)
	}
	if tokenType == "access" {
		token, err := c.ParseToken(string(tokenBytes))
		if err != nil {
			return err
		}
		c.AccessToken = token.Raw
	} else if tokenType == "refresh" {
		c.RefreshToken = string(tokenBytes)
	}
	return nil
}

func (c *GitopsClient) DeleteTokenFromCache(tokenType string) error {
	var tokenFilePath string
	if tokenType == "access" {
		tokenFilePath = c.CachePath + "/access_token"
	} else if tokenType == "refresh" {
		tokenFilePath = c.CachePath + "/refresh_token"
	} else {
		return errors.New("Unknown tokenType: " + tokenType)
	}
	if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
		return nil
	}
	f, err := os.Create(tokenFilePath)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}
