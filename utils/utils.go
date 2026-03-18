package utils

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Options struct {
	Domains       []string
	Force         bool
	Headers       []string
	Ips           []string
	Paths         []string
	Port          int
	Proxy         string
	Threads       int
	Timeout       int
	Tls           bool
	Verbose       bool
	Verify        bool
	RetryBaseline int
	Wordlist      []string
}

type Job struct {
	Baseline *FuzzResult
	Domain   string
	Ip       string
	Path     string
}

func EnumerateVhosts(opts *Options) {
	domains := PermuteDomains(opts.Wordlist, opts.Domains)

	threadChan := make(chan Job, opts.Threads)
	var wg sync.WaitGroup

	fuzzer := &Fuzzer{
		Options: opts,
		Client:  GetClient(opts),
	}

	for i := 0; i < cap(threadChan); i++ {
		go worker(fuzzer, threadChan, &wg)
	}

	type failure struct {
		ip   string
		path string
	}
	var failures []failure

	getBaseline := func(ip, path string) (*FuzzResult, error) {
		var domain string
		if len(domains) > 0 {
			domain = fmt.Sprintf("%s.%s", uuid.NewString(), domains[0])
		} else {
			domain = uuid.NewString()
		}
		return fuzzer.FuzzHost(ip, domain, path)
	}

	queueBaseline := func(ip, path string, baseline *FuzzResult) {
		for _, domain := range domains {
			wg.Add(1)
			threadChan <- Job{
				Baseline: baseline,
				Domain:   domain,
				Ip:       ip,
				Path:     path,
			}
		}
	}

	for _, ip := range opts.Ips {
		for _, path := range opts.Paths {
			baseUrl := fuzzer.GetBaseUrl(ip, path)
			if opts.Verbose {
				fmt.Printf("[!] Obtaining baseline on: %s\n", baseUrl)
			}
			baseline, err := getBaseline(ip, path)
			if err != nil {
				fmt.Printf("[!] Failed to obtain baseline (%s): %s\n", baseUrl, err.Error())
				failures = append(failures, failure{ip, path})
				continue
			}
			queueBaseline(ip, path, baseline)
		}
	}

	for r := 0; r < opts.RetryBaseline && len(failures) > 0; r++ {
		if opts.Verbose {
			fmt.Printf("[!] Retrying %d failed baselines (attempt %d/%d)\n", len(failures), r+1, opts.RetryBaseline)
		}
		var nextFailures []failure
		for _, f := range failures {
			baseline, err := getBaseline(f.ip, f.path)
			if err != nil {
				if opts.Verbose {
					baseUrl := fuzzer.GetBaseUrl(f.ip, f.path)
					fmt.Printf("[!] Failed to obtain baseline (%s) during retry: %s\n", baseUrl, err.Error())
				}
				nextFailures = append(nextFailures, f)
				continue
			}
			queueBaseline(f.ip, f.path, baseline)
		}
		failures = nextFailures
	}

	if opts.Force && len(failures) > 0 {
		baseline := &FuzzResult{
			ContentLength: 0,
			Response:      "",
			Status:        0,
		}
		for _, f := range failures {
			queueBaseline(f.ip, f.path, baseline)
		}
	}
	wg.Wait()
	close(threadChan)
}

func worker(f *Fuzzer, jobs chan Job, wg *sync.WaitGroup) {
	for job := range jobs {
		result, resp, err := f.TestDomain(job.Ip, job.Domain, job.Path, job.Baseline.Response)
		if resp == nil || err != nil {
			if err != nil {
				fmt.Printf("[!] [%s] [%s] [0] [0] %s -> %s\n", job.Ip, job.Path, job.Domain, err.Error())
			} else {
				fmt.Printf("[!] [%s] [%s] [0] [0] %s -> Error generating response\n", job.Ip, job.Path, job.Domain)
			}
		} else if result == true {
			if f.Options.Verify {
				if f.CompareGeneric(job.Domain, job.Path, resp.Response) {
					fmt.Printf("[+] [%s] [%s] [%d] [%d] %s\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
				} else {
					fmt.Printf("[-] [%s] [%s] [%d] [%d] %s is different than the baseline, but is not different than public facing domain\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
				}
			} else {
				fmt.Printf("[+] [%s] [%s] [%d] [%d] %s\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
			}
		} else if f.Options.Verbose {
			fmt.Printf("[-] [%s] [%s] [%d] [%d] %s is not different than the baseline\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
		}
		wg.Done()
	}
}

func PermuteDomains(wordlist []string, domainList []string) []string {
	var domains []string
	var dnSet bool = len(domainList) > 0

	for _, guess := range wordlist {
		if dnSet {
			for _, domain := range domainList {
				domains = append(domains, fmt.Sprintf("%s.%s", guess, domain))
			}
		} else {
			domains = append(domains, guess)
		}
	}

	return domains
}
