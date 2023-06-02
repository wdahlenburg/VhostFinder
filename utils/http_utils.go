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

type Fuzzer struct {
	Client  *http.Client
	Options *Options
}

type FuzzResult struct {
	ContentLength int64
	Response      string
	Status        int
}

func (f *Fuzzer) FuzzHost(ip string, domain string, path string) (*FuzzResult, error) {
	tls := f.Options.Tls
	port := f.Options.Port

	uri := ""
	if tls {
		uri += fmt.Sprintf("https://%s", ip)
	} else {
		uri += fmt.Sprintf("http://%s", ip)
	}

	if tls && port != 443 {
		uri += fmt.Sprintf(":%d", port)
	} else if !tls && port != 80 {
		uri += fmt.Sprintf(":%d", port)
	}

	uri += path

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	f.setHeaders(req)

	// Override the host header
	req.Host = domain

	resp, err := f.Client.Do(req)
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

func (f *Fuzzer) TestDomain(ip string, domain string, path string, baseline string) (bool, *FuzzResult, error) {
	fuzzedResponse, err := f.FuzzHost(ip, domain, path)
	if fuzzedResponse == nil || err != nil {
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

func (f *Fuzzer) getGeneric(domain string, path string) (string, error) {
	uri := fmt.Sprintf("https://%s%s", domain, path)
	if f.Options.Tls == false {
		uri = fmt.Sprintf("http://%s%s", domain, path)
	}

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	f.setHeaders(req)

	resp, err := f.Client.Do(req)
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

func (f *Fuzzer) CompareGeneric(domain string, path string, resp string) bool {
	publicResp, err := f.getGeneric(domain, path)
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

	// If there is a difference detected (some results) then report this as successful
	return len(diff) != 0
}

func (f *Fuzzer) GetBaseUrl(ip string, path string) string {
	scheme := "http"
	if f.Options.Tls {
		scheme += "s"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, ip, f.Options.Port, path)
}

func (f *Fuzzer) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "VhostFinder")
	for _, v := range f.Options.Headers {
		parts := strings.SplitN(v, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if strings.ToLower(key) != "host" {
			req.Header.Set(key, val)
		}
	}
}

func GetClient(opts *Options) *http.Client {
	dialer := &net.Dialer{
		Timeout: time.Duration(opts.Timeout) * time.Second,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		DisableKeepAlives:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       time.Duration(opts.Timeout) * time.Second,
		TLSHandshakeTimeout:   time.Duration(opts.Timeout) * time.Second,
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
