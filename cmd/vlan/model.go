package vlan

import "net"

type IPType uint

const (
	IPTypeIpv4 IPType = 1
	IPTypeIpv6 IPType = 2
)

type IPGroup struct {
	IpType              IPType
	EgressUnfloatingIPs []IP
	EgressFloatingIPs   []IP
	AppIPs              []string
}

type IP struct {
	IPCidr    string
	IsManager bool
}

type Vlan struct {
	Name    string
	MacAddr string
	MTU     int
	IPs     []IPGroup
	TagID   uint16
}

type NetworkInterface struct {
	Name          string
	MacAddr       string
	MTU           int
	IPs           []IPGroup
	InvalidAppIPs []string
	// Vlans         []Vlan
}

type Route struct {
	Dst net.IPNet
	Dev string
	Src net.IP
}
