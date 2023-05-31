package utils

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Options struct {
	Ips      []string
	Wordlist string
	Domains  []string
	Threads  int
	Port     int
	Tls      bool
	Verbose  bool
	Verify   bool
	Paths    []string
}

type Job struct {
	Baseline string
	Domain   string
	Ip       string
	Path     string
	Port     int
	Tls      bool
}

func EnumerateVhosts(opts *Options) {
	domains, err := ReadDomains(opts.Wordlist, opts.Domains)
	if err != nil {
		fmt.Printf(err.Error())
	}

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
			baseline, err := FuzzHost(ip, opts.Tls, uuid.NewString(), opts.Port, path)
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
		result, resp, err := TestDomain(job.Ip, job.Tls, job.Domain, job.Port, job.Path, job.Baseline)
		if err != nil {
			fmt.Printf("[!] [%s] [%s] %s -> %s\n", job.Ip, job.Path, job.Domain, err.Error())
		} else if result == true {
			if opts.Verify {
				if CompareGeneric(opts, job.Domain, resp) {
					fmt.Printf("[+] [%s] [%s] %s\n", job.Ip, job.Path, job.Domain)
				} else {
					fmt.Printf("[-] [%s] [%s] %s is different than the baseline, but is not different than public facing domain\n", job.Ip, job.Path, job.Domain)
				}
			} else {
				fmt.Printf("[+] [%s] [%s] %s\n", job.Ip, job.Path, job.Domain)
			}
		} else if opts.Verbose {
			fmt.Printf("[-] [%s] [%s] %s is not different than the baseline\n", job.Ip, job.Path, job.Domain)
		}
		wg.Done()
	}
}
