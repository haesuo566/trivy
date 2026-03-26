//go:build mage_schema

package main

import (
	"log"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("invalid schema command args: %s", os.Args)
	}

	switch os.Args[2] {
	case "generate":
		log.Println("schema generation is no longer supported (IaC removed)")
	case "verify":
		log.Println("schema verification is no longer supported (IaC removed)")
	}
}
