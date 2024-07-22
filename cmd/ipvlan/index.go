package ipvlan

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	IptablesTimeoutSec = 5
	NetnsName          = "sag"
	vethRootName       = "veth0_root"
	vethSagName        = "veth0_sag"
	vethRootIP         = "172.16.200.1/24"
	vethSagIP          = "172.16.200.2/24"
)

type HandleNs func() error

// ConnectNs 为了 ns:root 与 ns:sag 通讯，创建 veth peer 并配置 ip
// ip link add veth0_root type veth peer name veth0_sag netns sag
// ip link set veth0_root up
// ip -n sag link set veth0_sag up
// ip addr add 172.16.200.1/24 dev veth0_root
// ip -n sag addr add 172.16.200.2/24 dev veth0_sag
func ConnectNs() error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vethRootName},
		PeerName:  vethSagName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	vethRoot, err := netlink.LinkByName(vethRootName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(vethRoot); err != nil {
		return err
	}
	sagNs, err := netns.GetFromName(NetnsName)
	if err != nil {
		return err
	}
	defer sagNs.Close()

	vethSag, err := netlink.LinkByName(vethSagName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetNsFd(vethSag, int(sagNs)); err != nil {
		return err
	}

	if err := netns.Set(sagNs); err != nil {
		return err
	}

	// 启动 veth0_sag 接口
	veth0Sag, err := netlink.LinkByName("veth0_sag")
	if err != nil {
		log.Fatalf("获取 veth0_sag 接口失败: %v", err)
	}
	if err := netlink.LinkSetUp(veth0Sag); err != nil {
		log.Fatalf("启动 veth0_sag 失败: %v", err)
	}

	// 设置 veth0_sag IP 地址
	addr0Sag := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP("172.16.200.2"),
		Mask: net.CIDRMask(24, 32),
	}}
	if err := netlink.AddrAdd(veth0Sag, addr0Sag); err != nil {
		log.Fatalf("设置 veth0_sag IP 地址失败: %v", err)
	}

	// 切换回默认命名空间
	defaultNs, err := netns.Get()
	if err != nil {
		log.Fatalf("获取默认命名空间失败: %v", err)
	}
	defer defaultNs.Close()
	if err := netns.Set(defaultNs); err != nil {
		log.Fatalf("切换回默认命名空间失败: %v", err)
	}

	// 设置 veth0_root IP 地址
	addr0Root := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP("172.16.200.1"),
		Mask: net.CIDRMask(24, 32),
	}}
	if err := netlink.AddrAdd(vethRoot, addr0Root); err != nil {
		log.Fatalf("设置 veth0_root IP 地址失败: %v", err)
	}

	fmt.Println("veth 接口对已成功创建和配置")
	return nil
}

func AloneAdd(ipPort string, destIpPort string) error {
	appIpStr, _ := getIPAndPort(ipPort)
	destIpStr, _ := getIPAndPort(destIpPort)

	// 找到源站匹配的 ipvlan，没有匹配到则报错
	_, _, err := MatchNsIpvlan(destIpStr)
	if err != nil {
		return err
	}

	// ipvlan 添加 ip 地址
	appIpvlanName, appMaskNumber, err := MatchNsIpvlan(appIpStr)
	if err != nil {
		return err
	}
	if err := NsAddAddr(appIpvlanName, appIpStr, appMaskNumber); err != nil {
		return err
	}

	return nil
}

func AloneDel(ipPort string) error {
	appIpStr, _ := getIPAndPort(ipPort)

	// ipvlan 删除 ip 地址
	appIpvlanName, appMaskNumber, err := MatchNsIpvlan(appIpStr)
	if err != nil {
		return err
	}
	if err := NsDelAddr(appIpvlanName, appIpStr, appMaskNumber); err != nil {
		return err
	}

	return nil
}

func NsPortNAT(appIpStr, appPortStr, toPort string) error {
	protocol := iptables.ProtocolIPv4
	if net.ParseIP(appIpStr).To4() == nil {
		protocol = iptables.ProtocolIPv6
	}
	return NsDo(func() error {
		t, err := iptables.New(iptables.IPFamily(protocol), iptables.Timeout(IptablesTimeoutSec))
		if err != nil {
			return err
		}
		rule := []string{
			"-p", "tcp", "-d", appIpStr, "--dport", appPortStr, "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%s", appIpStr, toPort),
		}
		if err := t.Append("nat", "PREROUTING", rule...); err != nil {
			return err
		}
		return nil
	})
}

// NsDelRoutes 判断是否有路由需要删除，路由的 ip 地址属于这个 IpCIDR 内，这删除这个路由。
func NsDelRoutes(ipStr string, maskNumber int) error {
	return NsDo(func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipStr, maskNumber))
		if err != nil {
			return err
		}
		for _, link := range links {
			routes, err := netlink.RouteList(link, 0)
			if err != nil {
				return err
			}
			for _, route := range routes {
				ones, bits := route.Dst.Mask.Size()
				if ones == bits {
					if ipNet.Contains(route.Dst.IP) {
						if err := netlink.RouteDel(&route); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
}

func NsDelAddr(ipvlanName, ipStr string, maskNumber int) error {
	return NsDo(func() error {
		link, err := netlink.LinkByName(ipvlanName)
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ipStr, maskNumber))
		if err != nil {
			return err
		}
		if err := netlink.AddrDel(link, addr); err != nil {
			return err
		}
		return nil
	})
}

// NsAddRoute 找到源站匹配的 ipvlan，查看 destIpvlanName 是否存在 ip，不存在 ip 就需要添加路由
func NsAddRoute(targetIP string, ipvlanName string) error {
	return NsDo(func() error {
		ip := net.ParseIP(targetIP)
		if ip == nil {
			return fmt.Errorf("invalid ip address: %v", targetIP)
		}
		targetIpCIDR := targetIP + "/24"
		if ip.To4() == nil {
			targetIpCIDR = targetIP + "/128"
		}
		println(targetIpCIDR)

		_, ipNet, err := net.ParseCIDR(targetIpCIDR)
		if err != nil {
			return err
		}

		link, err := netlink.LinkByName(ipvlanName)
		if err != nil {
			return err
		}

		route := &netlink.Route{
			Dst:       ipNet,
			LinkIndex: link.Attrs().Index,
		}

		if err := netlink.RouteAdd(route); err != nil {
			return err
		}
		return nil
	})
}

func IsNsAddrExisted(ipvlanName string) (bool, error) {
	isExisted := false
	err := NsDo(func() error {
		link, err := netlink.LinkByName(ipvlanName)
		if err != nil {
			return err
		}
		addrs, err := netlink.AddrList(link, 0)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if !strings.HasPrefix(addr.String(), "fe80::") {
				// 有 ip
				isExisted = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return isExisted, nil
}

func NsDo(h HandleNs) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originNS, _ := netns.Get()
	defer originNS.Close()
	defer netns.Set(originNS)

	ns, err := netns.GetFromName(NetnsName)
	if err != nil {
		return err
	}
	if err := netns.Set(ns); err != nil {
		return err
	}
	return h()
}

// MatchNsIpvlan 根据 IP，返回所属网段的 ipvlan 名称，没有匹配到返回错误, 可能匹配多个，子网掩码最大的优先级最高。
func MatchNsIpvlan(ipStr string) (ipvlanName string, maskNumber int, err error) {
	var ipvlans map[string][]string
	err = NsDo(func() error {
		ipvlanMaps, err := GetIpvlanList()
		if err != nil {
			return err
		}
		ipvlans = ipvlanMaps
		return nil
	})
	if err != nil {
		return
	}

	ips := make(map[string]string) // key: mask, val: NIC name

	for name, ipCIDRs := range ipvlans {
		for _, ipCIDR := range ipCIDRs {
			isContain, err := ipCIDRContain(ipStr, ipCIDR)
			if err != nil {
				return ipvlanName, maskNumber, err
			}
			if isContain {
				ips[ipCIDR] = name
			}
		}
	}
	if len(ips) == 0 {
		return ipvlanName, maskNumber, fmt.Errorf("not match ipvlan: %v", ipStr)
	}

	// 排序，获取 mask 最大的。
	for ipCIDR, name := range ips {
		_, cidr, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			return ipvlanName, maskNumber, err
		}
		ones, _ := cidr.Mask.Size()
		if ones > maskNumber {
			ipvlanName = name
			maskNumber = ones
		}
	}

	return ipvlanName, maskNumber, nil
}

func NsAddAddr(ipvlanName, ipStr string, maskNumber int) error {
	return NsDo(func() error {
		link, err := netlink.LinkByName(ipvlanName)
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ipStr, maskNumber))
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		return nil
	})
}

func GetIpvlanList() (map[string][]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	res := make(map[string][]string)

	for _, link := range links {
		if link.Type() == "ipvlan" {
			addrs, err := netlink.AddrList(link, 0) // netlink.AddrList(link, netlink.FAMILY_ALL)
			if err != nil {
				return nil, err
			}
			ips := make([]string, 0)
			for _, addr := range addrs {
				ips = append(ips, addr.IPNet.String())
			}
			res[link.Attrs().Name] = ips
		}
	}

	return res, nil
}

func getIPAndPort(ipPortStr string) (ipStr string, portStr string) {
	index := strings.LastIndex(ipPortStr, ":")
	ipStr = ipPortStr[:index]
	portStr = ipPortStr[index+1:]
	return
}

func ipCIDRContain(ip string, ipScope string) (bool, error) {
	ipSource := net.ParseIP(ip)
	if ipSource == nil {
		return false, fmt.Errorf("ip is invalid")
	}
	_, ipNet, err := net.ParseCIDR(ipScope)
	if err != nil {
		return false, err
	}
	if ipNet.Contains(ipSource) {
		return true, nil
	} else {
		return false, nil
	}
}
