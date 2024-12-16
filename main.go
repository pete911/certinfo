package main

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
	"os"
	"strconv"
	"strings"
	"sync"
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
	if flags.NoExpired {
		certificatesFiles = certificatesFiles.RemoveExpired()
	}
	if flags.NoDuplicate {
		certificatesFiles = certificatesFiles.RemoveDuplicates()
	}
	if flags.SubjectLike != "" {
		certificatesFiles = certificatesFiles.SubjectLike(flags.SubjectLike)
	}
	if flags.IssuerLike != "" {
		certificatesFiles = certificatesFiles.IssuerLike(flags.IssuerLike)
	}
	if flags.SortExpiry {
		certificatesFiles = certificatesFiles.SortByExpiry()
	}
	if flags.Expiry {
		PrintCertificatesExpiry(certificatesFiles)
		return
	}
	if flags.PemOnly {
		PrintPemOnly(certificatesFiles, flags.Chains)
		return
	}
	PrintCertificatesLocations(certificatesFiles, flags.Chains, flags.Pem, flags.Extensions)
}

func LoadCertificatesLocations(flags Flags) cert.CertificateLocations {

	var certificateLocations cert.CertificateLocations
	if flags.Clipboard {
		certificateLocations = append(certificateLocations, cert.LoadCertificateFromClipboard())
	}

	if len(flags.Args) > 0 {
		certificateLocations = append(certificateLocations, loadFromArgs(flags.Args, flags.Insecure)...)
	}

	if isStdin() {
		certificateLocations = append(certificateLocations, cert.LoadCertificateFromStdin())
	}

	if len(certificateLocations) > 0 {
		return certificateLocations
	}

	// no stdin and no args
	flags.Usage()
	os.Exit(0)
	return nil
}

func loadFromArgs(args []string, insecure bool) cert.CertificateLocations {

	out := make(chan cert.CertificateLocation)
	go func() {
		var wg sync.WaitGroup
		for _, arg := range args {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if isTCPNetworkAddress(arg) {
					out <- cert.LoadCertificatesFromNetwork(arg, insecure)
					return
				}
				out <- cert.LoadCertificatesFromFile(arg)
			}()
		}
		wg.Wait()
		close(out)
	}()

	// load certificates from the channel
	certsByArgs := make(map[string]cert.CertificateLocation)
	for location := range out {
		certsByArgs[location.Path] = location
	}

	// sort certificates by input arguments
	var certsSortedByArgs cert.CertificateLocations
	for _, arg := range args {
		certsSortedByArgs = append(certsSortedByArgs, certsByArgs[arg])
	}
	return certsSortedByArgs
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

	if (info.Mode() & os.ModeCharDevice) == 0 {
		return true
	}
	return false
}
