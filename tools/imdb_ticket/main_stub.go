//go:build !phase6native

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "imdb_ticket requires the phase6native build tag and native SCMP library")
	os.Exit(1)
}
