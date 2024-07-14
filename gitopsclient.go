package gitopsclient

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/go-resty/resty/v2"
)

func NewGitopsClient(config GitopsClientConfig) (*GitopsClient, error) {
	// TODO: validate config
	c := GitopsClient{
		GitopsApiURI:        config.GitopsApiURI,
		RestyClient:         resty.New(),
		CachePath:           config.CachePath,
		JwksURI:             config.JwksURI,
		TokenURI:            config.TokenURI,
		GrantType:           config.GrantType,
		ClientId:            config.ClientId,
		ClientSecret:        config.ClientSecret,
		Scopes:              config.Scopes,
		Username:            config.Username,
		Password:            config.Password,
		AuthURI:             config.AuthURI,
		RedirectURI:         config.RedirectURI,
		AuthzListenerSocket: config.AuthzListenerSocket,
		Debug:               config.Debug,
		AccessToken:         "",
		RefreshToken:        "",
	}
	return &c, nil
}

func (c *GitopsClient) handleResponse(resp *resty.Response) error {
	if resp.StatusCode() > 299 {
		return errors.New(
			"GitopsClient error: " + resp.Status() + ", Body: " + string(resp.Body()),
		)
	}
	if c.Debug {
		fmt.Println("Response Info:")
		fmt.Println("  Status Code:" + strconv.Itoa(resp.StatusCode()))
		fmt.Println("  Status     :" + resp.Status())
		fmt.Println("  Proto      :" + resp.Proto())
		fmt.Println("  Time       :" + resp.Time().String())
		fmt.Println("  Received At:" + resp.ReceivedAt().String())
		fmt.Println("  Body       :\n  " + resp.String())
	}
	return nil
}

func (c *GitopsClient) PostInstanceOrder(order_request InstanceOrder) (Instance, error) {
	uri := c.GitopsApiURI + "/instances"
	var instance Instance
	err := c.GetTokenFromCache("access")
	if err != nil {
		return instance, err
	}
	resp, err := c.RestyClient.R().
		SetAuthToken(c.AccessToken).
		SetBody(order_request).
		SetResult(&instance).
		Post(uri)
	if err == nil {
		err = c.handleResponse(resp)
	}
	return instance, err
}

func (c *GitopsClient) GetInstance(instance_id string) (Instance, error) {
	uri := c.GitopsApiURI + "/instances/" + instance_id
	var instance Instance
	err := c.GetTokenFromCache("access")
	if err != nil {
		return instance, err
	}
	resp, err := c.RestyClient.R().
		SetAuthToken(c.AccessToken).
		SetResult(&instance).
		Get(uri)
	if err == nil {
		err = c.handleResponse(resp)
	}
	return instance, err
}

func (c *GitopsClient) GetInstances() ([]string, error) {
	uri := c.GitopsApiURI + "/instances"
	var instances []string
	err := c.GetTokenFromCache("access")
	if err != nil {
		return instances, err
	}
	resp, err := c.RestyClient.R().
		SetResult(&instances).
		Get(uri)
	if err == nil {
		err = c.handleResponse(resp)
	}
	return instances, err
}

func (c *GitopsClient) PutInstance(instance_id string, instance_update InstanceUpdate) (Instance, error) {
	uri := c.GitopsApiURI + "/instances/" + instance_id
	var instance Instance
	err := c.GetTokenFromCache("access")
	if err != nil {
		return instance, err
	}
	resp, err := c.RestyClient.R().
		SetAuthToken(c.AccessToken).
		SetBody(instance_update).
		SetResult(&instance).
		Put(uri)
	if err == nil {
		err = c.handleResponse(resp)
	}
	return instance, err
}

func (c *GitopsClient) DeleteInstance(instance_id string) error {
	uri := c.GitopsApiURI + "/instances/" + instance_id
	err := c.GetTokenFromCache("access")
	if err != nil {
		return err
	}
	resp, err := c.RestyClient.R().
		SetAuthToken(c.AccessToken).
		Delete(uri)
	if err == nil {
		err = c.handleResponse(resp)
	}
	return err
}
