package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

type Flags struct {
	Usage    func()
	Expiry   bool
	Insecure bool
	Chains   bool
	Pem      bool
	PemOnly  bool
	Version  bool
	Args     []string
}

func ParseFlags() (Flags, error) {

	var flags Flags
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.BoolVar(&flags.Expiry, "expiry", getBoolEnv("CERTINFO_EXPIRY", false),
		"print expiry of certificates")
	flagSet.BoolVar(&flags.Insecure, "insecure", getBoolEnv("CERTINFO_INSECURE", false),
		"whether a client verifies the server's certificate chain and host name (only applicable for host)")
	flagSet.BoolVar(&flags.Chains, "chains", getBoolEnv("CERTINFO_CHAINS", false),
		"whether to print verified chains as well (only applicable for host)")
	flagSet.BoolVar(&flags.Pem, "pem", getBoolEnv("CERTINFO_PEM", false),
		"whether to print pem as well")
	flagSet.BoolVar(&flags.PemOnly, "pem-only", getBoolEnv("CERTINFO_PEM_ONLY", false),
		"whether to print only pem (useful for downloading certs from host)")
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
