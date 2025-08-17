package api

import (
	"log"
	"os"
	"strconv"
	"time"
)

var ips = make(map[string]int)

func IsRateLimited(ip string) bool {
	maxRequests, exists := os.LookupEnv("MAX_REQUESTS")
	if !exists {
		log.Fatal("MISSING env \"MAX_REQUESTS\"")
	}
	rqs, ok := ips[ip]
	if !ok{
		rqs = 1
		go func() {
			time.Sleep(time.Second*60)
			delete(ips,ip)
		}()
	}
	ips[ip]++
	rqsLimit, err := strconv.Atoi(maxRequests)
	if err != nil{
		log.Fatalf("Failed at converting %v into int: %v",maxRequests,err.Error())
	}
	return rqs >= rqsLimit
}
