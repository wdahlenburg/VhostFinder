package utils

import (
	"strings"
	"bufio"
	"os"
)

func ReadDomains(wordlist string, tld string) ([]string, []string, error) {
	var domains []string
	var domainNames []string

	f, err := os.Open(wordlist)

	if err != nil {
		return nil, nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	// If domain name was set
	// User has the ability to set multiple domain names, seperated by a comma
	// We split the domainname string by the comma 
	if len(strings.TrimSpace(tld)) > 0 {
		dn := strings.Split(tld, ",")
		for _, d := range dn {
			d = strings.TrimSpace(d)
			//If we have an empty index, skip it
			if len(d) == 0 {
				continue
			}
			domainNames = append(domainNames, d)
		}
	}

	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return domains, domainNames, nil
}
