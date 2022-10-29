package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/wdahlenburg/VhostFinder/utils"
)

func main() {
	var (
		ip         string
		wordlist   string
		domains    string
		domainList []string
		threads    int
		port       int
		tls        bool
		verbose    bool
		verify     bool
		path       string
	)

	flag.StringVar(&ip, "ip", "", "IP Address to Fuzz")
	flag.StringVar(&wordlist, "wordlist", "", "File of FQDNs or subdomain prefixes to fuzz for")
	flag.StringVar(&domains, "domains", "", "Optional domain or comma seperated list to append to a subdomain wordlist (Ex: example1.com,example2.com)")
	flag.IntVar(&threads, "threads", 10, "Number of threads to use")
	flag.BoolVar(&tls, "tls", true, "Use TLS")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&verify, "verify", false, "Verify vhost is different than public url")
	flag.StringVar(&path, "path", "/", "Custom path to send during fuzzing")
	flag.IntVar(&port, "port", 443, "Port to use")

	flag.Parse()

	if ip == "" || wordlist == "" {
		fmt.Printf("[!] Usage: vhost_finder -ip 10.8.0.1 -wordlist domains.txt\n")
		flag.PrintDefaults()
		return
	}

	if len(strings.TrimSpace(domains)) > 0 {
		for _, domain := range strings.Split(domains, ",") {
			domain = strings.TrimSpace(domain)
			if len(domain) > 0 {
				domainList = append(domainList, domain)
			}
		}
	}

	fmt.Printf("[!] Finding vhosts!\n")
	opts := &utils.Options{
		Ip:       ip,
		Wordlist: wordlist,
		Domains:  domainList,
		Threads:  threads,
		Tls:      tls,
		Verbose:  verbose,
		Verify:   verify,
		Path:     path,
		Port:     port,
	}
	utils.EnumerateVhosts(opts)
}
