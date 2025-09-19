package ratelimit

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
func getIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff,",")[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
func IsRateLimited(r *http.Request) bool {
	ip := getIP(r)
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
