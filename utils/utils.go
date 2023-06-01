package utils

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Options struct {
	BaselineInterval int
	Domains          []string
	Headers          []string
	Ips              []string
	Paths            []string
	Port             int
	Proxy            string
	Threads          int
	Timeout          int
	Tls              bool
	Verbose          bool
	Verify           bool
	Wordlist         []string
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
		Client:  getClient(opts),
	}

	for i := 0; i < cap(threadChan); i++ {
		go worker(fuzzer, threadChan, &wg)
	}

	interval := opts.BaselineInterval

	for _, ip := range opts.Ips {
		shouldContinue := true
		for _, path := range opts.Paths {
			var lastDomain string
			baseUrl := fuzzer.GetBaseUrl(ip, path)
			baseline, err := takeBaseline(fuzzer, ip, lastDomain, path)
			if err != nil {
				fmt.Printf("[!] Failed to obtain baseline (%s): %s\n", baseUrl, err.Error())
			} else {
				for i, domain := range domains {
					// If the baseline interval is (1-100], obtain a new baseline at the given percentage of domains
					if interval > 0 {
						if int(i%(interval*len(domains)/100)) == 0 {
							baseline, err = takeBaseline(fuzzer, ip, lastDomain, path)
							if err != nil {
								fmt.Printf("[!] Failed to re-obtain baseline (%s): %s\n", baseUrl, err.Error())
								shouldContinue = false
							}
						}
					}

					if shouldContinue {
						wg.Add(1)
						threadChan <- Job{
							Baseline: baseline,
							Domain:   domain,
							Ip:       ip,
							Path:     path,
						}
						lastDomain = domain
					}
				}
			}
		}
	}
	wg.Wait()
	close(threadChan)
}

func takeBaseline(fuzzer *Fuzzer, ip string, domain string, path string) (*FuzzResult, error) {
	var baseline *FuzzResult
	var err error
	baseUrl := fuzzer.GetBaseUrl(ip, path)
	if fuzzer.Options.Verbose {
		fmt.Printf("[!] Obtaining baseline on: %s\n", baseUrl)
	}

	if domain != "" {
		baseline, err = fuzzer.FuzzHost(ip, fmt.Sprintf("%s.%s", uuid.NewString(), domain), path)
	} else {
		baseline, err = fuzzer.FuzzHost(ip, uuid.NewString(), path)
	}
	if err != nil {
		return nil, err
	}
	return baseline, nil
}

func worker(f *Fuzzer, jobs chan Job, wg *sync.WaitGroup) {
	for job := range jobs {
		result, resp, err := f.TestDomain(job.Ip, job.Domain, job.Path, job.Baseline.Response)
		if err != nil {
			fmt.Printf("[!] [%s] [%s] [%d] [%d] %s -> %s\n", job.Ip, job.Path, job.Domain, resp.Status, resp.ContentLength, err.Error())
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
