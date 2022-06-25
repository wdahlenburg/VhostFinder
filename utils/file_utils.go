package utils

import (
	"bufio"
	"os"
)

func ReadDomains(Wordlist string) ([]string, error) {
	var domains []string
	f, err := os.Open(Wordlist)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
