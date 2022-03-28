package main

import (
	"github.com/Kindling-project/kindling/collector/application"
	"log"
    "github.com/Kindling-project/kindling/collector/version"
)

func main() {
	app, err := application.New()
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}
	
	//print version information
	log.Printf("GitCommitInfo:%s\n", version.Version())

	
	err = app.Run()
	if err != nil {
		log.Fatalf("Failed to run application: %v", err)
	}

}
