package main

import (
	"filehost/internal/api"
	"filehost/internal/db"
	"log"
)

func main() {
	log.Println("Creating tables")
	if err := db.Initialize(); err != nil {
		log.Fatalf("An error ocurred while trying to connect to postgres: %v", err.Error())
	}
	log.Println("Started listening")
	if err := api.Listen(); err != nil {
		log.Fatalf("An error ocurred while listening to API: %v", err.Error())
	}
}
