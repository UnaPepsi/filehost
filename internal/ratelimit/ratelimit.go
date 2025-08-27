package ratelimit

import (
	"log"
	"os"
	"strconv"
	"time"
)

var ips = make(map[string]int)

var maxRequests int
func init(){
	var err error
	maxRequestsStr, exists := os.LookupEnv("MAX_REQUESTS")
	if !exists {
		log.Fatal("MISSING env \"MAX_REQUESTS\"")
	}
	maxRequests, err = strconv.Atoi(maxRequestsStr)
	if err != nil{
		log.Fatalf("Failed at converting %v into int: %v",maxRequestsStr,err.Error())
	}
}
func MaxRequests() int {
	return maxRequests
}
func IsRateLimited(ip string) bool {
	rqs, ok := ips[ip]
	if !ok{
		rqs = 1
		go func() {
			time.Sleep(time.Second*60)
			delete(ips,ip)
		}()
	}
	ips[ip]++
	return rqs >= maxRequests
}
