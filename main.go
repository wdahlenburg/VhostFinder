package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/wdahlenburg/VhostFinder/utils"
)

type options struct {
	domains  goflags.StringSlice
	headers  goflags.StringSlice
	ip       goflags.StringSlice
	ips      goflags.StringSlice
	path     goflags.StringSlice
	paths    goflags.StringSlice
	port     int
	proxy    string
	threads  int
	tls      bool
	verbose  bool
	verify   bool
	wordlist goflags.StringSlice
}

func main() {
	var (
		ips   []string
		paths []string
	)

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("VhostFinder")
	opt := &options{}

	flagSet.CreateGroup("required", "Required",
		flagSet.StringSliceVarP(&opt.ip, "ip", "", nil, "IP Address to Fuzz", goflags.StringSliceOptions),
		flagSet.StringSliceVar(&opt.ips, "ips", nil, "File list of IPs", goflags.FileStringSliceOptions),
		flagSet.StringSliceVar(&opt.wordlist, "wordlist", nil, "File of FQDNs or subdomain prefixes to fuzz for", goflags.FileStringSliceOptions),
	)

	flagSet.StringSliceVarP(&opt.domains, "domain", "d", nil, "Domain(s) to append to a subdomain wordlist (Ex: example1.com)", goflags.StringSliceOptions)
	flagSet.StringSliceVarP(&opt.headers, "header", "H", nil, "Custom header(s) for each request", goflags.StringSliceOptions)
	flagSet.StringSliceVarP(&opt.path, "path", "p", nil, "Custom path(s) to send during fuzzing", goflags.StringSliceOptions)
	flagSet.StringSliceVar(&opt.paths, "paths", nil, "File list of custom paths", goflags.FileStringSliceOptions)
	flagSet.IntVar(&opt.port, "port", 443, "Port to use")
	flagSet.StringVar(&opt.proxy, "proxy", "", "Proxy (Ex: http://127.0.0.1:8080)")
	flagSet.IntVarP(&opt.threads, "threads", "t", 10, "Number of threads to use")
	flagSet.BoolVar(&opt.tls, "tls", true, "Use TLS")
	flagSet.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose mode")
	flagSet.BoolVar(&opt.verify, "verify", false, "Verify vhost is different than public url")

	if err := flagSet.Parse(); err != nil {
		fmt.Printf("[!] Could not parse flags: %s\n", err)
	}

	if (len(opt.ip) == 0 && len(opt.ips) == 0) || len(opt.wordlist) == 0 {
		os.Args = append(os.Args, "-h")
		flagSet.CommandLine.Usage()

		fmt.Println()
		fmt.Println("[!] Please ensure that IPs are set with either the \"ip\" or \"ips\" flags. Also include the \"wordlist\" flag.")
		return
	}

	for _, ip := range append(opt.ips, opt.ip...) {
		ip = strings.TrimSpace(ip)
		if len(ip) > 0 {
			ips = append(ips, ip)
		}
	}

	for _, path := range append(opt.paths, opt.path...) {
		path = strings.TrimSpace(path)
		if !strings.HasPrefix(path, "/") {
			path = fmt.Sprintf("/%s", path)
		}
		paths = append(paths, path)
	}

	if len(paths) == 0 {
		paths = []string{"/"}
	}

	fmt.Printf("[!] Finding vhosts!\n")
	opts := &utils.Options{
		Domains:  opt.domains,
		Headers:  opt.headers,
		Ips:      ips,
		Paths:    paths,
		Port:     opt.port,
		Proxy:    opt.proxy,
		Threads:  opt.threads,
		Tls:      opt.tls,
		Verbose:  opt.verbose,
		Verify:   opt.verify,
		Wordlist: opt.wordlist,
	}
	utils.EnumerateVhosts(opts)
}
