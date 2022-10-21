package utils

import (
	"strings"
	"bufio"
	"fmt"
	"os"
)

func ReadDomains(wordlist string, tld string) ([]string, error) {
	var domains []string
	f, err := os.Open(wordlist)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	var tldSet bool = len(strings.TrimSpace(tld)) > 0

	for scanner.Scan() {
		
		if tldSet {
			// If domain name was set, prepend line to domain name
			// This assumes the user supplied a list of hostnames/subdomains that doesn't contain the domain name 
			fullDomain := fmt.Sprintf("%s.%s", strings.TrimSpace(scanner.Text()), strings.TrimSpace(tld))
			domains = append(domains, fullDomain)
		} else {
			domains = append(domains, scanner.Text())
		}
		
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
