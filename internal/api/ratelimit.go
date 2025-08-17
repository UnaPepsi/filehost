package api

import (
	"log"
	"os"
	"strconv"
)

var ips = make(map[string]int)

func IsRateLimited(ip string) bool {
	maxRequests, exists := os.LookupEnv("MAX_REQUESTS")
	if !exists {
		log.Fatal("MISSING env \"MAX_REQUESTS\"")
	}
	rqs, ok := ips[ip]
	if !ok{
		ips[ip] = 1
		rqs = 1
		go func() {
			delete(ips,ip)
		}()
	}
	rqsLimit, err := strconv.Atoi(maxRequests)
	if err != nil{
		log.Fatalf("Failed at converting %v into int: %v",maxRequests,err.Error())
	}
	return rqs >= rqsLimit
}
