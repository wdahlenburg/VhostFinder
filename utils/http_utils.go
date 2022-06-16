package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/wdahlenburg/HttpComparison"
)

func FuzzHost(ip string, tls bool, domain string, port int, path string) (string, error) {
	url := ""
	if tls {
		url += fmt.Sprintf("https://%s", domain)
	} else {
		url += fmt.Sprintf("http://%s", domain)
	}

	if tls && port != 443 {
		url += fmt.Sprintf(":%d", port)
	} else if !tls && port != 80 {
		url += fmt.Sprintf(":%d", port)
	}

	url += path

	client := getClient(ip, port)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "VhostFinder")
	req.Header.Set("Accept-Encoding", "*")
	req.Host = domain

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

func TestDomain(ip string, tls bool, domain string, port int, path string, baseline string) (bool, string, error) {
	fuzzedResponse, err := FuzzHost(ip, tls, domain, port, path)
	if err != nil {
		return false, "", err
	}

	var responses []string
	responses = append(responses, fuzzedResponse)

	similarity_scanner := &HttpComparison.Similarity{
		Threshhold: 0.50,
	}
	diff, err := similarity_scanner.CompareStrResponses(baseline, responses)
	if err != nil {
		fmt.Printf("[!] %s\n", err.Error())
		return false, "", err
	}

	// If there is a differnce detected (some results) then report this as successful
	return len(diff) != 0, fuzzedResponse, nil
}

func getGeneric(opts *Options, domain string) (string, error) {
	url := fmt.Sprintf("https://%s%s", domain, opts.Path)
	if opts.Tls == false {
		url = fmt.Sprintf("http://%s%s", domain, opts.Path)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "VhostFinder")
	req.Header.Set("Accept-Encoding", "*")

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

func CompareGeneric(opts *Options, domain string, resp string) bool {
	publicResp, err := getGeneric(opts, domain)
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

func getClient(ip string, port int) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	webclient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = fmt.Sprintf("%s:%d", ip, port)
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return webclient
}
