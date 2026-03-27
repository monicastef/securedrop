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

	server, err := mdns.NewServer(&mdns.Config{
		Zone: service,
	})
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
	
					// only this service
					if !strings.Contains(entry.Name, "_securedrop._tcp") {
						continue
					}
	
					if entry.AddrV4 == nil {
						continue
					}
	
					peerPort := entry.Port
	
					// skip self
					if strconv.Itoa(peerPort) == port {
						continue
					}
	
					// filter random devices
					if peerPort < 9000 || peerPort > 9100 {
						continue
					}
	
					peer := entry.AddrV4.String() + ":" + strconv.Itoa(peerPort)
	
					if !app.HasPeer(peer) {
						fmt.Println("[mDNS] discovered", peer)
						go connectWithRetry(app, peer)
					}
					
				}
			}()
	
			params := &mdns.QueryParam{
				Service: "_securedrop._tcp",
				Entries: entriesCh,
				Timeout: time.Second * 2,
			}
	
			mdns.Query(params)
	
			close(entriesCh)
	
			// time.Sleep(15 * time.Second)
			
			if len(app.ListPeers()) > 0 {
				time.Sleep(30 * time.Second) // slow once connected
			} else {
				time.Sleep(5 * time.Second) // faster until first peer
			}
		}
	}()

	_ = server
}

func mustAtoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}