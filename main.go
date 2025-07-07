package main

import (
	"fmt"
	"github.com/pete911/certinfo/pkg/cert"
	"github.com/pete911/certinfo/pkg/print"
	"log/slog"
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
	setLogger(flags.Verbose)

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
		print.Expiry(certificatesFiles)
		return
	}
	if flags.PemOnly {
		print.Pem(certificatesFiles, flags.Chains)
		return
	}
	print.Locations(certificatesFiles, flags.Chains, flags.Pem, flags.Extensions, flags.Signature)
}

func setLogger(verbose bool) {
	level := slog.LevelError
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func LoadCertificatesLocations(flags Flags) cert.CertificateLocations {

	var certificateLocations cert.CertificateLocations
	if len(flags.Args) > 0 {
		certificateLocations = append(certificateLocations, loadFromArgs(flags.Args, flags.ServerName, flags.Insecure)...)
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

func loadFromArgs(args []string, serverName string, insecure bool) cert.CertificateLocations {

	out := make(chan cert.CertificateLocation)
	go func() {
		var wg sync.WaitGroup
		for _, arg := range args {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if isTCPNetworkAddress(arg) {
					out <- cert.LoadCertificatesFromNetwork(arg, serverName, insecure)
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
