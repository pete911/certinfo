package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pete911/certinfo/pkg/cert"
)

var Version = "dev"

func main() {

	flags, err := ParseFlags()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if flags.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	certificatesFiles := LoadCertificatesLocations(flags)
	if flags.Expiry {
		PrintCertificatesExpiry(certificatesFiles)
		return
	}
	if flags.PemOnly {
		PrintPemOnly(certificatesFiles, flags.Chains)
		return
	}
	PrintCertificatesLocations(certificatesFiles, flags.Chains, flags.Pem)
}

func LoadCertificatesLocations(flags Flags) []cert.CertificateLocation {

	if isStdin() {
		certificateLocation, err := cert.LoadCertificateFromStdin()
		if err != nil {
			printCertFileError("stdin", err)
			return nil
		}
		return []cert.CertificateLocation{certificateLocation}
	}

	// no stdin and not args
	if len(flags.Args) == 0 {
		flags.Usage()
		os.Exit(0)
	}

	var certificateLocations []cert.CertificateLocation
	for _, arg := range flags.Args {

		var certificateLocation cert.CertificateLocation
		var err error
		if isTCPNetworkAddress(arg) {
			certificateLocation, err = cert.LoadCertificatesFromNetwork(arg, flags.Insecure)
		} else {
			certificateLocation, err = cert.LoadCertificatesFromFile(arg)
		}

		if err != nil {
			printCertFileError(arg, err)
			continue
		}
		certificateLocations = append(certificateLocations, certificateLocation)
	}
	return certificateLocations
}

func printCertFileError(fileName string, err error) {

	fmt.Printf("--- [%s] ---\n", nameFormat(fileName, 0))
	fmt.Println(err)
	fmt.Println()
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

func isStdin() bool {

	info, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("checking stdin: %v\n", err)
		return false
	}

	if info.Mode()&os.ModeCharDevice == os.ModeCharDevice || info.Size() <= 0 {
		return false
	}
	return true
}
