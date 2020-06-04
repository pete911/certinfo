package main

import (
	"flag"
	"os"
	"strconv"
)

type Flags struct {
	Expiry bool
	Args   []string
}

func ParseFlags() (Flags, error) {

	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	expiry := f.Bool("expiry", getBoolEnv("CERTINFO_EXPIRY", false), "print expiry of certificates")
	if err := f.Parse(os.Args[1:]); err != nil {
		return Flags{}, err
	}
	return Flags{Expiry: boolValue(expiry), Args: f.Args()}, nil
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

func boolValue(v *bool) bool {

	if v == nil {
		return false
	}
	return *v
}
