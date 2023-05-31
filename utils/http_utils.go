package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/wdahlenburg/HttpComparison"
)

type FuzzResult struct {
	ContentLength int64
	Response      string
	Status        int
}

func FuzzHost(opts *Options, ip string, tls bool, domain string, port int, path string) (*FuzzResult, error) {
	url := ""
	if tls {
		url += fmt.Sprintf("https://%s", ip)
	} else {
		url += fmt.Sprintf("http://%s", ip)
	}

	if tls && port != 443 {
		url += fmt.Sprintf(":%d", port)
	} else if !tls && port != 80 {
		url += fmt.Sprintf(":%d", port)
	}

	url += path

	client := getClient(opts, ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, opts)

	// Override the host header
	req.Host = domain

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}

	return &FuzzResult{
		ContentLength: resp.ContentLength,
		Response:      string(result),
		Status:        resp.StatusCode,
	}, nil
}

func TestDomain(opts *Options, ip string, tls bool, domain string, port int, path string, baseline string) (bool, *FuzzResult, error) {
	fuzzedResponse, err := FuzzHost(opts, ip, tls, domain, port, path)
	if err != nil {
		return false, nil, err
	}

	var responses []string
	responses = append(responses, fuzzedResponse.Response)

	similarity_scanner := &HttpComparison.Similarity{
		Threshhold: 0.50,
	}
	diff, err := similarity_scanner.CompareStrResponses(baseline, responses)
	if err != nil {
		fmt.Printf("[!] %s\n", err.Error())
		return false, nil, err
	}

	// If there is a difference detected (some results) then report this as successful
	return len(diff) != 0, fuzzedResponse, nil
}

func getGeneric(opts *Options, domain string, path string) (string, error) {
	uri := fmt.Sprintf("https://%s%s", domain, path)
	if opts.Tls == false {
		uri = fmt.Sprintf("http://%s%s", domain, path)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	if opts.Proxy != "" {
		proxy, err := url.Parse(opts.Proxy)
		if err != nil {
			return "", err
		}
		tr.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req, opts)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	result, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func CompareGeneric(opts *Options, domain string, path string, resp string) bool {
	publicResp, err := getGeneric(opts, domain, path)
	if err != nil {
		// DNS failure or timeout occurs then return true
		fmt.Printf("[!] %s\n", err.Error())
		return true
	}

	var responses []string
	responses = append(responses, resp)

	similarity_scanner := &HttpComparison.Similarity{
		Threshhold: 0.50,
	}
	diff, err := similarity_scanner.CompareStrResponses(publicResp, responses)
	if err != nil {
		fmt.Printf("[!] %s\n", err.Error())
		return true
	}

	// If there is a differnce detected (some results) then report this as successful
	return len(diff) != 0
}

func getClient(opts *Options, ip string, port int) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	if opts.Proxy != "" {
		proxy, err := url.Parse(opts.Proxy)
		if err != nil {
			fmt.Printf("[!] Unable to parse proxy: %s\n", err.Error())
		} else {
			tr.Proxy = http.ProxyURL(proxy)
		}
	}

	webclient := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return webclient
}

func setHeaders(req *http.Request, opts *Options) {
	req.Header.Set("User-Agent", "VhostFinder")
	for _, v := range opts.Headers {
		parts := strings.SplitN(v, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if strings.ToLower(key) != "host" {
			req.Header.Set(key, val)
		}
	}
}

func GetBaseUrl(opts *Options, ip string, path string) string {
	scheme := "http"
	if opts.Tls {
		scheme += "s"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, ip, opts.Port, path)
}
