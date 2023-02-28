package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	for {
		// Fetch the latest DGA blocklist in CSV format from Cisco Talos
		resp, err := http.Get("https://talosintelligence.com/documents/ip-blacklist")
		if err != nil {
			log.Fatalf("Error fetching DGA blocklist: %s", err)
		}
		defer resp.Body.Close()

		// Parse the blocklist data and extract the list of DGA domains
		scanner := bufio.NewScanner(resp.Body)
		var domains []string
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if len(domain) > 0 && !strings.HasPrefix(domain, "#") {
				domains = append(domains, domain)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error parsing DGA blocklist data: %s", err)
		}

		// Write the list of DGA domains to a text file
		err = writeDomainsToFile(domains)
		if err != nil {
			log.Fatalf("Error writing DGA blocklist file: %s", err)
		}

		// Generate iptables rules to block traffic to the listed DGA domains
		cmd := exec.Command("/bin/sh", "-c", "iptables -F && while read domain; do iptables -A INPUT -p tcp -m string --string \"$domain\" -j DROP; done < dga-blocklist.txt")
		err = cmd.Run()
		if err != nil {
			log.Fatalf("Error generating iptables rules: %s", err)
		}

		// Sleep for 24 hours before fetching the next update
		time.Sleep(24 * time.Hour)
	}
}

func writeDomainsToFile(domains []string) error {
	f, err := os.Create("dga-blocklist.txt")
	if err != nil {
		return err
	}
	defer f.Close()

	for _, domain := range domains {
		_, err := f.WriteString(domain + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}
