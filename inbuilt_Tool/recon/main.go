package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type SubfinderResult struct {
	Host string `json:"host"`
}

type DNSXResult struct {
	Host  string   `json:"host"`
	A     []string `json:"a,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

func extractSubdomains(inputFile string) ([]string, error) {
	var subs []string
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var result SubfinderResult
		err := json.Unmarshal([]byte(scanner.Text()), &result)
		if err == nil {
			subs = append(subs, result.Host)
		}
	}
	return subs, scanner.Err()
}

func runDNSX(subs []string, outputFile string) error {
	tmpInput := "temp_input.txt"
	f, _ := os.Create(tmpInput)
	for _, sub := range subs {
		f.WriteString(sub + "\n")
	}
	f.Close()

	cmd := exec.Command("dnsx", "-silent", "-json", "-l", tmpInput, "-o", outputFile)
	err := cmd.Run()
	os.Remove(tmpInput)
	return err
}

func parseDNSXResults(outputFile string) ([]DNSXResult, error) {
	var results []DNSXResult
	file, err := os.Open(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r DNSXResult
		err := json.Unmarshal([]byte(scanner.Text()), &r)
		if err == nil {
			results = append(results, r)
		}
	}
	return results, scanner.Err()
}

func writeValidatedResults(results []DNSXResult, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// --------------- CLI ---------------

var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "Recon tool using subfinder + dnsx",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run subdomain scan using subfinder and dnsx",
	Run: func(cmd *cobra.Command, args []string) {
		if domain == "" {
			color.Red("[-] Please provide a domain using --domain")
			os.Exit(1)
		}

		color.Cyan("[*] Running Subfinder...")
		exec.Command("subfinder", "-d", domain, "-silent", "-oJ", "-o", rawFile).Run()

		color.Yellow("[*] Extracting subdomains...")
		subs, err := extractSubdomains(rawFile)
		if err != nil {
			color.Red("[-] Failed to extract subdomains: %v", err)
			os.Exit(1)
		}

		color.Cyan("[*] Running DNSX validation...")
		runDNSX(subs, outputFile)

		results, _ := parseDNSXResults(outputFile)
		writeValidatedResults(results, outputFile)

		color.Green("\n[+] Live Hosts:")
		for _, r := range results {
			if len(r.A) > 0 {
				color.Green("%s → %s", r.Host, strings.Join(r.A, ", "))
			} else if r.CNAME != "" {
				color.Magenta("%s → CNAME: %s", r.Host, r.CNAME)
			}
		}

		color.Green("\n[✔] Output saved to %s", outputFile)
	},
}


var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate subdomains from a file using dnsx",
	Run: func(cmd *cobra.Command, args []string) {
		if inputFile == "" || domain == "" {
			color.Red("[-] Please provide both --file and --domain")
			os.Exit(1)
		}

		color.Yellow("[*] Validating domains in %s", inputFile)
		subs, err := extractSubdomains(inputFile)
		if err != nil {
			color.Red("[-] Failed to read input: %v", err)
			os.Exit(1)
		}

		runDNSX(subs, outputFile)
		results, _ := parseDNSXResults(outputFile)
		writeValidatedResults(results, outputFile)

		color.Green("\n[✔] Validated results written to %s", outputFile)
	},
}


// Shared flags
var domain string
var rawFile string
var outputFile string
var inputFile string

func init() {
	// scan
	scanCmd.Flags().StringVar(&domain, "domain", "", "Target domain (required)")
	scanCmd.Flags().StringVar(&rawFile, "raw", "output/raw.json", "Raw output file")
	scanCmd.Flags().StringVar(&outputFile, "output", "output/validated.json", "Validated output file")

	// validate
	validateCmd.Flags().StringVar(&inputFile, "file", "", "Input subdomain file")
	validateCmd.Flags().StringVar(&domain, "domain", "", "Target domain")
	validateCmd.Flags().StringVar(&outputFile, "output", "output/validated.json", "Output file")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(validateCmd)
}

func main() {
	os.MkdirAll("output", 0755)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
