package web

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	SetTimeout(timeout time.Duration)
}

var Client HTTPClient

type client struct {
	c *http.Client
}

func init() {
	Client = client{
		c: &http.Client{},
	}
}

func (c client) Do(req *http.Request) (*http.Response, error) {
	return c.c.Do(req)
}

func (c client) SetTimeout(timeout time.Duration) {
	c.c.Timeout = timeout
}

type KV struct {
	Key   string
	Value string
}

func Post(url string, timeout time.Duration, b []byte, headers ...KV) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}

	return do(req, timeout, headers...)
}

func do(req *http.Request, timeout time.Duration, headers ...KV) (int, []byte, error) {
	req.Header.Set("Content-Type", "application/json") // default to json
	for _, v := range headers {
		req.Header.Set(v.Key, v.Value)
	}

	// a value of 0 means no timeout
	if timeout.Minutes() != 0 {
		Client.SetTimeout(timeout)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}
