package main

import (
	"flag"
	"fmt"

	"github.com/wdahlenburg/VhostFinder/utils"
)

func main() {
	var (
		ip      string
		file    string
		threads int
		port    int
		tls     bool
		verbose bool
		verify  bool
		path    string
	)

	flag.StringVar(&ip, "ip", "", "IP Address to Fuzz")
	flag.StringVar(&file, "file", "", "File of domain names to fuzz for")
	flag.IntVar(&threads, "threads", 10, "Number of threads to use")
	flag.BoolVar(&tls, "tls", true, "Use TLS (Default: true)")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&verify, "verify", false, "Verify vhost is different than public url")
	flag.StringVar(&path, "path", "/", "Custom path to send during fuzzing")
	flag.IntVar(&port, "port", 443, "Port to use")

	flag.Parse()

	if ip == "" || file == "" {
		fmt.Printf("[!] Usage: vhost_finder -ip 10.8.0.1 -file domains.txt\n")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("[!] Finding vhosts!\n")
	opts := &utils.Options{
		Ip:       ip,
		Filename: file,
		Threads:  threads,
		Tls:      tls,
		Verbose:  verbose,
		Verify:   verify,
		Path:     path,
		Port:     port,
	}
	utils.EnumerateVhosts(opts)
}
