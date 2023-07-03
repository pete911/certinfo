package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"golang.design/x/clipboard"
)

type Flags struct {
	Usage       func()
	Expiry      bool
	NoDuplicate bool
	NoExpired   bool
	Insecure    bool
	Chains      bool
	Pem         bool
	PemOnly     bool
	Version     bool
	Clipboard   bool
	Args        []string
}

func ParseFlags() (Flags, error) {

	var flags Flags
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.BoolVar(&flags.Expiry, "expiry", getBoolEnv("CERTINFO_EXPIRY", false),
		"print expiry of certificates")
	flagSet.BoolVar(&flags.NoDuplicate, "no-duplicate", getBoolEnv("CERTINFO_NO_DUPLICATE", false),
		"do not print duplicate certificates")
	flagSet.BoolVar(&flags.NoExpired, "no-expired", getBoolEnv("CERTINFO_NO_EXPIRED", false),
		"do not print expired certificates")
	flagSet.BoolVar(&flags.Insecure, "insecure", getBoolEnv("CERTINFO_INSECURE", false),
		"whether a client verifies the server's certificate chain and host name (only applicable for host)")
	flagSet.BoolVar(&flags.Chains, "chains", getBoolEnv("CERTINFO_CHAINS", false),
		"whether to print verified chains as well (only applicable for host)")
	flagSet.BoolVar(&flags.Pem, "pem", getBoolEnv("CERTINFO_PEM", false),
		"whether to print pem as well")
	flagSet.BoolVar(&flags.PemOnly, "pem-only", getBoolEnv("CERTINFO_PEM_ONLY", false),
		"whether to print only pem (useful for downloading certs from host)")
	if isClipboardSupported() {
		flagSet.BoolVar(&flags.Clipboard, "clipboard", false,
			"read input from clipboard")
	}
	flagSet.BoolVar(&flags.Version, "version", getBoolEnv("CERTINFO_VERSION", false),
		"certinfo version")

	flagSet.Usage = func() {
		fmt.Fprint(flagSet.Output(), "Usage: certinfo [flags] [<file>|<host:port> ...]\n")
		flagSet.PrintDefaults()
	}
	flags.Usage = flagSet.Usage

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return Flags{}, err
	}
	flags.Args = flagSet.Args()
	return flags, nil
}

func getBoolEnv(envName string, defaultValue bool) bool {

	env, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}

	if intValue, err := strconv.ParseBool(env); err == nil {
		return intValue
	}
	return defaultValue
}

func isClipboardSupported() bool {

	if err := clipboard.Init(); err == nil {
		return true
	}

	return false
}
