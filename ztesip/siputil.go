package ztesip

import (
	"fmt"
	"net"
)

func ParseSip() {
	fmt.Printf("from sip tuil\n")
}

func LocalIps() []net.IP {
	ips := []net.IP{}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				//fmt.Printf("ipNet %+v %b\n",ip,ip.IsGlobalUnicast())
			case *net.IPAddr:
				ip = v.IP
				//fmt.Printf("ipAddr %+v\n",ip)
			}
			if ip.IsGlobalUnicast() {
				ips = append(ips, ip)
			}

		}
	}
	return ips
}
