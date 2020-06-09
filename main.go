package main

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
	"os"
	"strconv"
	"strings"
)

var Version = "dev"

func main() {

	flags, err := ParseFlags()
	if err != nil {
		fmt.Sprintf("cannot parse flags: %v", err)
		os.Exit(1)
	}

	if flags.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	certificatesFiles := LoadCertificatesLocations(flags.Args, flags.Insecure)
	if flags.Expiry {
		PrintCertificatesExpiry(certificatesFiles)
		return
	}
	PrintCertificatesLocations(certificatesFiles)
}

func LoadCertificatesLocations(args []string, insecure bool) []cert.CertificateLocation {

	var certificateLocations []cert.CertificateLocation
	for _, arg := range args {

		var certificateLocation cert.CertificateLocation
		var err error
		if isTCPNetworkAddress(arg) {
			certificateLocation, err = cert.LoadCertificatesFromNetwork(arg, insecure)
		} else {
			certificateLocation, err = cert.LoadCertificatesFromFile(arg)
		}

		if err != nil {
			fmt.Printf("--- [%s] ---\n", nameFormat(arg, 0))
			fmt.Println(err)
			fmt.Println()
			continue
		}
		certificateLocations = append(certificateLocations, certificateLocation)
	}
	return certificateLocations
}

func isTCPNetworkAddress(arg string) bool {

	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return false
	}
	return true
}
