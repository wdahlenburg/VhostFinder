package utils

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
)

type Options struct {
	Ip       	string
	Wordlist 	string
	DomainName  string
	Threads  	int
	Port     	int
	Tls      	bool
	Verbose  	bool
	Verify   	bool
	Path     	string
}

func EnumerateVhosts(opts *Options) {
	domains, domainNames, err := ReadDomains(opts.Wordlist, opts.DomainName)
	if err != nil {
		fmt.Printf(err.Error())
	}

	if opts.Verbose {
		fmt.Printf("[!] Obtaining baseline\n")
	}
	baseline, err := FuzzHost(opts.Ip, opts.Tls, uuid.NewString(), opts.Port, opts.Path)
	if err != nil {
		fmt.Printf("[!] Failed to obtain baseline: %s\n", err.Error())
		os.Exit(1)
	}

	var dnSet bool = len(domainNames) > 0

	threadChan := make(chan string, opts.Threads)
	var wg sync.WaitGroup

	for i := 0; i < cap(threadChan); i++ {
		go worker(opts, threadChan, baseline, &wg)
	}
	for _, domain := range domains {
		// Add domain name append to thread channel so we can preserve thread count limits
		if dnSet {
			for _, d := range domainNames{
				wg.Add(1)
				threadChan <- fmt.Sprintf("%s.%s", domain, d)
			}
		} else {
			wg.Add(1)
			threadChan <- domain
		}
	}
	wg.Wait()
	close(threadChan)
}

func worker(opts *Options, domains chan string, baseline string, wg *sync.WaitGroup) {
	for domain := range domains {
		result, resp, err := TestDomain(opts.Ip, opts.Tls, domain, opts.Port, opts.Path, baseline)
		if err != nil {
			fmt.Printf("[!] %s\n", err.Error())
		} else if result == true {
			if opts.Verify {
				if CompareGeneric(opts, domain, resp) {
					fmt.Printf("[+] %s\n", domain)
				} else {
					fmt.Printf("[-] %s is different than the baseline, but is not different than public facing domain\n", domain)
				}
			} else {
				fmt.Printf("[+] %s\n", domain)
			}
		} else if opts.Verbose {
			fmt.Printf("[-] %s is not different than the baseline\n", domain)
		}
		wg.Done()
	}
}
