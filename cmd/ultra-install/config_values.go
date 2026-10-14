package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runConfigValuesCommand(args []string) {
	flags := flag.NewFlagSet("config-values", flag.ExitOnError)
	source := flags.String("config", "install.config", "canonical deployment parameters")
	_ = flags.Parse(args)
	values, err := installplan.DiagnosticConfig(*source)
	exitOnErr("diagnostic configuration", err)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, err = fmt.Fprintf(os.Stdout, "%s\x00%s\x00", key, values[key])
		exitOnErr("diagnostic output", err)
	}
}
