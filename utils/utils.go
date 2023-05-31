package utils

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Options struct {
	Domains  []string
	Headers  []string
	Ips      []string
	Paths    []string
	Port     int
	Proxy    string
	Threads  int
	Tls      bool
	Verbose  bool
	Verify   bool
	Wordlist []string
}

type Job struct {
	Baseline *FuzzResult
	Domain   string
	Ip       string
	Path     string
	Port     int
	Tls      bool
}

func EnumerateVhosts(opts *Options) {
	domains := PermuteDomains(opts.Wordlist, opts.Domains)

	threadChan := make(chan Job, opts.Threads)
	var wg sync.WaitGroup

	for i := 0; i < cap(threadChan); i++ {
		go worker(opts, threadChan, &wg)
	}

	for _, ip := range opts.Ips {
		for _, path := range opts.Paths {
			baseUrl := GetBaseUrl(opts, ip, path)
			if opts.Verbose {
				fmt.Printf("[!] Obtaining baseline on: %s\n", baseUrl)
			}
			baseline, err := FuzzHost(opts, ip, opts.Tls, uuid.NewString(), opts.Port, path)
			if err != nil {
				fmt.Printf("[!] Failed to obtain baseline (%s): %s\n", baseUrl, err.Error())
			} else {
				for _, domain := range domains {
					wg.Add(1)
					threadChan <- Job{
						Baseline: baseline,
						Domain:   domain,
						Ip:       ip,
						Path:     path,
						Port:     opts.Port,
						Tls:      opts.Tls,
					}
				}
			}
		}
	}
	wg.Wait()
	close(threadChan)
}

func worker(opts *Options, jobs chan Job, wg *sync.WaitGroup) {
	for job := range jobs {
		result, resp, err := TestDomain(opts, job.Ip, job.Tls, job.Domain, job.Port, job.Path, job.Baseline.Response)
		if err != nil {
			fmt.Printf("[!] [%s] [%s] [%d] [%d] %s -> %s\n", job.Ip, job.Path, job.Domain, resp.Status, resp.ContentLength, err.Error())
		} else if result == true {
			if opts.Verify {
				if CompareGeneric(opts, job.Domain, job.Path, resp.Response) {
					fmt.Printf("[+] [%s] [%s] [%d] [%d] %s\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
				} else {
					fmt.Printf("[-] [%s] [%s] [%d] [%d] %s is different than the baseline, but is not different than public facing domain\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
				}
			} else {
				fmt.Printf("[+] [%s] [%s] [%d] [%d] %s\n", job.Ip, job.Path, resp.Status, resp.ContentLength, job.Domain)
			}
		} else if opts.Verbose {
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
