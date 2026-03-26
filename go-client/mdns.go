package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"os"
	"time"
	"strings"

	"github.com/hashicorp/mdns"
)

func startMDNS(app *App, port string) {
	// get local IP
	host, _ := os.Hostname()
	addr, _ := net.ResolveIPAddr("ip4", host)

	service, err := mdns.NewMDNSService(
		host,                  // instance name
		"_securedrop._tcp",    // service type
		"",                    // domain
		"",                    // host
		mustAtoi(port),        // port
		nil,                   // IPs (auto)
		nil,                   // TXT records
	)
	if err != nil {
		log.Fatal(err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[mDNS] advertising on", addr.IP, port)

	// discover
	go func() {
		for {
			entriesCh := make(chan *mdns.ServiceEntry, 4)
	
			go func() {
				for entry := range entriesCh {

					if !strings.Contains(entry.Name, "_securedrop._tcp") {
						continue
					}
	
					if entry.AddrV4 == nil {
						continue
					}
	
					peer := entry.AddrV4.String() + ":" + strconv.Itoa(entry.Port)
	
					// skip self
					if strconv.Itoa(entry.Port) == port {
						continue
					}
	
					fmt.Println("[mDNS] discovered", peer)
					go connectWithRetry(app, peer)
				}
			}()
	
			params := &mdns.QueryParam{
				Service: "_securedrop._tcp",
				Entries: entriesCh,
				Timeout: time.Second * 2,
			}
	
			mdns.Query(params)
	
			close(entriesCh)
	
			time.Sleep(5 * time.Second)
		}
	}()

	_ = server
}

func mustAtoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}