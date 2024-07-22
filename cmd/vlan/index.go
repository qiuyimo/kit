package vlan

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/duke-git/lancet/v2/condition"
	"github.com/duke-git/lancet/v2/slice"
	"github.com/go-ping/ping"
	"github.com/vishvananda/netlink"
)

var (
	ManageNIF    *NetworkInterface
	BusinessNIFs []*NetworkInterface
	mu           sync.Mutex
)

func Init() error {
	// 获取全部的物理网卡
	systemNIFs, err := getNetInterfacesBySystem()
	if err != nil {
		return err
	}

	// 从数据库中读取配置
	dbBusinessNIFs, err := getNetInterfacesByPersistent()
	if err != nil {
		return err
	}

	manageNIFName := "ens1" // todo(rain): 从配置文件中获取到管理网卡的名称
	newNIFs, removedNICNames, err := initNIF(systemNIFs, dbBusinessNIFs, manageNIFName)
	if err != nil {
		return err
	}
	BusinessNIFs = newNIFs
	// BusinessNIFsNameMap = newNIFsMap

	// 处理已经移除的物理网卡
	if len(removedNICNames) > 0 {
		m := make(map[string]*NetworkInterface)
		for _, v := range dbBusinessNIFs {
			m[v.Name] = v
		}
		for _, name := range removedNICNames {
			for _, group := range m[name].IPs {
				// 重新设置 应用ip 到网卡，走匹配规则，因为可能会有移除了 192.168.1.0/25，但其他网卡是 192.168.1.0/24
				for _, appIPCidr := range group.AppIPs {
					ip, _, err := net.ParseCIDR(appIPCidr)
					if err != nil {
						return err
					}
					if err := ApplyAppIP(ip.String()); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func initNIF(systemNIFs, dbBusinessNIFs []*NetworkInterface, manageNIFName string) ([]*NetworkInterface, []string, error) {
	if len(systemNIFs) == 0 {
		return nil, nil, fmt.Errorf("no network interfaces found")
	}

	// 如果删除了网卡，需要也能启动，网卡上的应用 ip 移动到第一个业务网卡，对应的出口 ip 抹除掉
	systemMapLinks := make(map[string]*NetworkInterface)
	for _, v := range systemNIFs {
		systemMapLinks[v.Name] = v
	}
	removedNICNames := make([]string, 0)
	for _, v := range dbBusinessNIFs {
		if _, ok := systemMapLinks[v.Name]; !ok {
			removedNICNames = append(removedNICNames, v.Name)
		}
	}

	// 生成 map 类型数据的全局变量
	dbBusinessNIFsNameMap := make(map[string]*NetworkInterface)
	for _, v := range dbBusinessNIFs {
		dbBusinessNIFsNameMap[v.Name] = v
	}

	newNIFs := make([]*NetworkInterface, 0)

	// 获取新的配置
	for _, v := range systemNIFs {
		if v.Name == manageNIFName {
			continue
		}
		if _, ok := dbBusinessNIFsNameMap[v.Name]; ok {
			newNIFs = append(newNIFs, dbBusinessNIFsNameMap[v.Name])
		} else {
			newNIFs = append(newNIFs, v)
		}
	}

	if len(removedNICNames) == len(dbBusinessNIFs) {
		return nil, nil, fmt.Errorf("not enough business network interfaces")
	}

	// fmt.Printf("removedNICNames: %v\n", removedNICNames)
	// for _, v := range newNIFs {
	// 	println(v.Name)
	// }

	return newNIFs, removedNICNames, nil
}

type m struct {
	name       string
	ipCIDR     string
	groupIndex int
}

// ApplyAppIP 把应用 ip 部署到对应的网卡上
func ApplyAppIP(appIP string) error {
	businessNIFs := GetNetInterfaceList()

	matched, err := MatchAppIP(appIP, businessNIFs)
	if err != nil {
		return err
	}

	// 匹配到
	if matched != nil {
		appIPCidr, err := getAppIPCidr(appIP, matched.ipCIDR)
		if err != nil {
			return err
		}
		if err := AddIPToIF(matched.name, appIPCidr); err != nil {
			return err
		}
		if err := UpdateBusinessNIFsAppIPCidr(appIPCidr, matched); err != nil {
			return err
		}
		return nil
	}

	// 没有匹配到，则使用第一个业务物理网卡
	if err := AddIPToIF(businessNIFs[0].Name, appIP); err != nil {
		return err
	}
	businessNIFs[0].InvalidAppIPs = append(businessNIFs[0].InvalidAppIPs, appIP)

	return nil
}

// getAppIPCidr 根据应用 ip 和 出口ipCIDR，计算出应用 ipCIDR
func getAppIPCidr(appIP string, egressIpCidr string) (string, error) {
	_, netIP, err := net.ParseCIDR(egressIpCidr)
	if err != nil {
		return "", err
	}
	if !netIP.Contains(net.ParseIP(appIP)) {
		return "", fmt.Errorf("app IP %s is not in CIDR %s", appIP, egressIpCidr)
	}
	netIP.IP = net.ParseIP(appIP)
	return netIP.String(), nil
}

func UpdateBusinessNIFsAppIPCidr(appIPCidr string, matched *m) error {
	for _, v := range BusinessNIFs {
		if v.Name == matched.name {
			v.IPs[matched.groupIndex].AppIPs = append(v.IPs[matched.groupIndex].AppIPs, appIPCidr)
			return nil
		}
	}
	return fmt.Errorf("business network interface %s not found", matched.name)
}

// MatchAppIP 根据已用ip，匹配出库 ip
// 当有出口 ip 时，用出口 ip 判断，当只有 接口 ip 时，用 接口 ip。
// 规则：判断应用 ip 是否属于出口 ip 的网段，当属于多个网段时，子网掩码大的优先级最高。
func MatchAppIP(appIP string, ifs []*NetworkInterface) (matchedItem *m, err error) {
	matched := make([]m, 0)

	for _, iface := range ifs {
		for i, group := range iface.IPs {
			isContain, err := isNetContainIP(appIP, group.EgressUnfloatingIPs[0].IPCidr)
			if err != nil {
				return nil, err
			}
			if isContain {
				matched = append(matched, m{
					name:       iface.Name,
					ipCIDR:     group.EgressUnfloatingIPs[0].IPCidr,
					groupIndex: i,
				})
			}
		}
	}

	if len(matched) == 0 {
		return nil, nil
	}

	return getMaskNumberMax(matched)
}

func getMaskNumberMax(ips []m) (*m, error) {
	res := new(m)
	maskNumber := 0

	for _, v := range ips {
		val := v
		_, cidr, err := net.ParseCIDR(val.ipCIDR)
		if err != nil {
			return nil, err
		}
		ones, _ := cidr.Mask.Size()
		if ones > maskNumber {
			maskNumber = ones
			res = &val
		}
	}
	return res, nil
}

func isNetContainIP(ipStr, ipCIDRStr string) (bool, error) {
	_, ipNet, err := net.ParseCIDR(ipCIDRStr)
	if err != nil {
		return false, err
	}
	return ipNet.Contains(net.ParseIP(ipStr)), nil
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

// 判断接口是否为物理网卡
func isPhysicalInterface(iface netlink.Link) bool {
	// 检查 /sys/class/net/<interface>/device 目录是否存在
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/device", iface.Attrs().Name))
	return !os.IsNotExist(err)
}

// GetNetInterfaceList 从全局变量中获取在sag管理平台中设置网络配置
func GetNetInterfaceList() []*NetworkInterface {
	return BusinessNIFs
}

// GetManagerInterface 第一个物理网卡就是管理网卡，管理网卡的参数从服务器上网卡信息获取
func GetManagerInterface() (netlink.Link, []netlink.Addr, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range links {
		if isPhysicalInterface(link) {
			addrs, err := netlink.AddrList(link, 0)
			if err != nil {
				return nil, nil, err
			}

			return link, addrs, nil
		}
	}
	return nil, nil, fmt.Errorf("not found interface")
}

func UpdateRoutes(routes []Route) error {
	for _, route := range routes {
		if err := UpdateRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// UpdateRoute 更新路由为浮动出口IP, 命令示例：ip route add 192.168.7.0/24 dev ens224 proto kernel scope link src 192.168.7.128
func UpdateRoute(route Route) error {
	// 查找网络接口
	link, err := netlink.LinkByName(route.Dev)
	if err != nil {
		return err
	}

	// 查找现有的路由
	routes, err := netlink.RouteList(link, 0)
	if err != nil {
		return err
	}

	deletedRoutes := make([]netlink.Route, 0)

	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == route.Dst.String() {
			if route.Src.Equal(route.Src) {
				fmt.Println("same route record is existed")
				return nil
			}
			deletedRoute := route
			if err := netlink.RouteDel(&route); err != nil {
				return err
			}
			deletedRoutes = append(deletedRoutes, deletedRoute)
			fmt.Printf("Deleted route: %s\n", route.String())
		}
	}

	// 添加新的路由
	newRoute := netlink.Route{
		Dst:       &route.Dst,
		LinkIndex: link.Attrs().Index,
		Src:       route.Src,
		Scope:     253, // netlink.SCOPE_LINK
		Protocol:  2,   // KERNEL
	}

	if err := netlink.RouteAdd(&newRoute); err != nil {
		// fmt.Printf("add failed, err: %v\n", err)
		if len(deletedRoutes) > 0 {
			for _, route := range deletedRoutes {
				if err := netlink.RouteAdd(&route); err != nil {
					fmt.Printf("add route failed, recover deleted route err: %v\n", err)
					return err
				}
			}
			fmt.Printf("recover deleted route success\n")
		}
		return err
	}

	fmt.Printf("Added route: %s\n", newRoute.String())
	return nil
}

func ipGroupEquals(a, b IPGroup, isManagerDiff bool) bool {
	if a.IpType != b.IpType {
		return false
	}

	if len(a.EgressUnfloatingIPs) != len(b.EgressUnfloatingIPs) {
		return false
	}

	for i := range a.EgressUnfloatingIPs {
		if !ipEquals(a.EgressUnfloatingIPs[i], b.EgressUnfloatingIPs[i], isManagerDiff) {
			return false
		}
	}

	if len(a.EgressFloatingIPs) != len(b.EgressFloatingIPs) {
		return false
	}

	for i := range a.EgressFloatingIPs {
		if !ipEquals(a.EgressFloatingIPs[i], b.EgressFloatingIPs[i], isManagerDiff) {
			return false
		}
	}

	return true
}

func ipEquals(a, b IP, isManagerDiff bool) bool {
	if isManagerDiff {
		return a.IsManager != b.IsManager && a.IPCidr == b.IPCidr
	}
	return a.IsManager == b.IsManager && a.IPCidr == b.IPCidr
}

func ipGroupsEqual(a, b []IPGroup) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !ipGroupEquals(a[i], b[i], false) {
			return false
		}
	}

	return true
}

func setMTU(interfaceName string, mtu int) error {
	// 获取网卡的链接
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	// 设置MTU
	err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	return nil
}

func getNetInterfacesBySystem() ([]*NetworkInterface, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	physicalInterfaces := make([]*NetworkInterface, 0)
	for _, link := range links {
		if isPhysicalInterface(link) {
			physicalInterfaces = append(physicalInterfaces, &NetworkInterface{
				Name:    link.Attrs().Name,
				MacAddr: link.Attrs().HardwareAddr.String(),
				MTU:     link.Attrs().MTU,
			})
		}
	}

	return physicalInterfaces, nil
}

// getNetInterfacesByPersistent 读取网卡配置
func getNetInterfacesByPersistent() ([]*NetworkInterface, error) {
	res := make([]*NetworkInterface, 0)

	// todo(rain): 从持久存储设备中获取网卡信息
	res = []*NetworkInterface{
		{
			Name: "ens160",
			MTU:  1500,
		},
	}

	return res, nil
}

// UpdateIpsToPhysicalValidation 数据校验
// ips 不能有重复的，都在同一个子网中，此网段未被使用，每个 ip 都是未被使用
func UpdateIpsToPhysicalValidation(newData NetworkInterface) error {
	// 没有设置 ips，则不需要校验
	if len(newData.IPs) == 0 {
		return nil
	}

	// ip 必须为有效的 ipCIDR 格式
	ips := make([]string, 0)
	for _, group := range newData.IPs {
		for _, ip := range group.EgressFloatingIPs {
			if _, _, err := net.ParseCIDR(ip.IPCidr); err != nil {
				return fmt.Errorf("invalid IPCidr: %s", ip.IPCidr)
			}
			ips = append(ips, ip.IPCidr)
		}
		for _, ip := range group.EgressUnfloatingIPs {
			if _, _, err := net.ParseCIDR(ip.IPCidr); err != nil {
				return fmt.Errorf("invalid IPCidr: %s", ip.IPCidr)
			}
			ips = append(ips, ip.IPCidr)
		}
	}

	// ips 不能有重复的
	if len(ips) != len(slice.Unique(ips)) {
		return fmt.Errorf("ips cannot be repeated")
	}

	// 都在同一个子网中
	isSame, err := isSameSubnet(ips)
	if err != nil {
		return err
	}
	if !isSame {
		return fmt.Errorf("ips are not on the same subnet")
	}

	// 此网段未被使用
	_, newNetIP, err := net.ParseCIDR(ips[0])
	if err != nil {
		return err
	}
	for _, nif := range BusinessNIFs {
		for _, group := range nif.IPs {
			if len(group.EgressUnfloatingIPs) == 0 {
				continue
			}
			ip, _, err := net.ParseCIDR(group.EgressUnfloatingIPs[0].IPCidr)
			if err != nil {
				return err
			}
			if newNetIP.Contains(ip) {
				return fmt.Errorf("subnet is used by %v", nif.Name)
			}
		}
	}

	// 每个 ip 都是未被使用
	for _, ipCIDR := range ips {
		ip, _, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			return err
		}
		isUsed, err := IsIPUsed(ip.String())
		if err != nil {
			return err
		}
		if isUsed {
			return fmt.Errorf("ip %v has been used", ipCIDR)
		}
	}

	return nil
}

// isSameSubnet 检查多个 CIDR 字符串是否在同一个网段内
func isSameSubnet(cidrs []string) (bool, error) {
	if len(cidrs) < 2 {
		return true, nil // 只有一个或没有 CIDR 字符串，认为它们在同一个网段内
	}

	// 解析第一个 CIDR
	_, firstNet, err := net.ParseCIDR(cidrs[0])
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s", cidrs[0])
	}

	// 遍历其余的 CIDR 并进行比较
	for _, cidr := range cidrs[1:] {
		_, currentNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR: %s", cidr)
		}

		// 比较网络地址和前缀长度
		if firstNet.IP.Equal(currentNet.IP.Mask(firstNet.Mask)) && firstNet.Mask.String() == currentNet.Mask.String() {
			continue
		} else {
			return false, nil
		}
	}

	return true, nil
}

func PreUpdateIpsToPhysical(newData NetworkInterface) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()

	nifs := GetNetInterfaceList()
	var oldData *NetworkInterface
	for _, v := range nifs {
		if v.Name == newData.Name {
			oldData = v
		}
	}
	if oldData == nil {
		return nil, fmt.Errorf("not found interface")
	}

	// 没有发生改变
	if ipGroupsEqual(newData.IPs, oldData.IPs) {
		return nil, nil
	}

	newIP2Manage := getAllIPMap(newData.IPs)
	oldIP2Manage := getAllIPMap(oldData.IPs)
	needChangeIPs, _ := getNeedChange(newIP2Manage, oldIP2Manage)

	appIPs := getNeedFloatingAppIPs(needChangeIPs, oldData)

	return appIPs, nil
}

func getNeedFloatingAppIPs(needChangeIPs map[string]bool, oldData *NetworkInterface) []string {
	needDel := make(map[string]struct{})
	for ip, b := range needChangeIPs {
		if b {
			needDel[ip] = struct{}{}
		}
	}
	// 只有 group 中的全部出口 ip 都需要删除，才需要移动对应的应用 ip 到第一个管理网卡上
	// 如何判断 group 中的 ip 是否全都需要删除呢？
	appIPs := make([]string, 0)

	if len(needDel) > 0 {
		for _, group := range oldData.IPs {
			isGroupDel := true
			for _, ip := range group.EgressUnfloatingIPs {
				if _, ok := needDel[ip.IPCidr]; !ok {
					isGroupDel = false
					break
				}
			}

			if isGroupDel {
				for _, ip := range group.EgressFloatingIPs {
					if _, ok := needDel[ip.IPCidr]; !ok {
						isGroupDel = false
						break
					}
				}
			}

			if isGroupDel {
				appIPs = append(appIPs, group.AppIPs...)
			}
		}
	}

	return appIPs
}

func UpdateIpsToPhysical(newData NetworkInterface) error {
	mu.Lock()
	defer mu.Unlock()

	nifs := GetNetInterfaceList()
	var oldData *NetworkInterface
	for _, v := range nifs {
		if v.Name == newData.Name {
			oldData = v
		}
	}
	if oldData == nil {
		return fmt.Errorf("not found interface")
	}

	if newData.MTU != oldData.MTU {
		if err := setMTU(newData.Name, newData.MTU); err != nil {
			return err
		}
	}

	if ipGroupsEqual(newData.IPs, oldData.IPs) {
		return nil
	}

	newIP2Manage := getAllIPMap(newData.IPs)
	oldIP2Manage := getAllIPMap(oldData.IPs)
	needChangeIPs, needChangeManage := getNeedChange(newIP2Manage, oldIP2Manage)

	needFloatingAppIPs := getNeedFloatingAppIPs(needChangeIPs, oldData)
	if len(needFloatingAppIPs) > 0 && !isFirstBusinessIF(newData.Name) {
		m := make(map[string]bool)
		for _, v := range needFloatingAppIPs {
			m[v] = false
		}
		if err := applyIPChanges(newData.Name, m); err != nil {
			return err
		}
	}

	if err := applyIPChanges(newData.Name, needChangeIPs); err != nil {
		return err
	}
	if err := applyManageChanges(needChangeManage); err != nil {
		return err
	}

	newRoutes, err := getNewRoutes(newData)
	if err != nil {
		return err
	}
	if err := UpdateRoutes(newRoutes); err != nil {
		return err
	}

	return nil
}

func isFirstBusinessIF(name string) bool {
	if BusinessNIFs[0].Name == name {
		return true
	}
	return false
}

func getNewRoutes(newData NetworkInterface) ([]Route, error) {
	routes := make([]Route, 0)
	var routeIpCIDR string
	for _, group := range newData.IPs {
		if len(group.EgressFloatingIPs) > 0 {
			routeIpCIDR = group.EgressFloatingIPs[0].IPCidr
		} else {
			if len(group.EgressUnfloatingIPs) == 0 {
				return routes, fmt.Errorf("no egress unfloating ip")
			}
			routeIpCIDR = group.EgressUnfloatingIPs[0].IPCidr
		}
		src, dst, err := net.ParseCIDR(routeIpCIDR)
		if err != nil {
			return routes, err
		}
		routes = append(routes, Route{
			Dst: *dst,
			Dev: newData.Name,
			Src: src,
		})
	}

	return routes, nil
}

// applyManageChanges 更新 ip 是否为管理 ip，needChangeManage，key: ipCIDR，val: bool
func applyManageChanges(needChangeManage map[string]bool) error {
	if len(needChangeManage) == 0 {
		return nil
	}
	// todo(rain)
	return nil
}

func getAllIPMap(iPGroups []IPGroup) map[string]bool {
	iP2Manage := make(map[string]bool)
	for _, group := range iPGroups {
		for _, floatingIP := range group.EgressFloatingIPs {
			iP2Manage[floatingIP.IPCidr] = floatingIP.IsManager
		}
		for _, unfloatingIP := range group.EgressUnfloatingIPs {
			iP2Manage[unfloatingIP.IPCidr] = unfloatingIP.IsManager
		}
	}
	return iP2Manage
}

// getNeedChange ipChange key: ip, val: true need add, false need del; ipManageChange key: ip, val: true need add, false need del
func getNeedChange(newIP2Manage, oldIP2Manage map[string]bool) (ipChange, ipManageChange map[string]bool) {
	ipChange = make(map[string]bool)
	ipManageChange = make(map[string]bool)

	for newIpCIDR, newIsManage := range newIP2Manage {
		oldIsManage, ok := oldIP2Manage[newIpCIDR]
		if ok {
			if newIsManage != oldIsManage {
				ipManageChange[newIpCIDR] = newIsManage
			}
		} else {
			ipChange[newIpCIDR] = true
			if newIsManage {
				ipManageChange[newIpCIDR] = newIsManage
			}
		}
	}

	for oldIpCIDR, oldIsManage := range oldIP2Manage {
		_, ok := newIP2Manage[oldIpCIDR]
		if !ok {
			ipChange[oldIpCIDR] = false
			if oldIsManage {
				ipManageChange[oldIpCIDR] = false
			}
		}
	}

	return
}

// AddIPToIF 给网卡添加 ip
func AddIPToIF(interfaceName string, ipCIDR string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	addr, err := netlink.ParseAddr(ipCIDR)
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}

	return nil
}

// applyIPChanges 更新 出口ip 的更改，changes, key: ipCIDR, val: true is add, false is del
func applyIPChanges(interfaceName string, changes map[string]bool) error {
	if len(changes) == 0 {
		return nil
	}

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	appliedChanges := make(map[string]bool)

	for ipCIDR, isAdd := range changes {
		addr, err := netlink.ParseAddr(ipCIDR)
		if err != nil {
			return err
		}
		if isAdd {
			err = netlink.AddrAdd(link, addr)
		} else {
			err = netlink.AddrDel(link, addr)
		}

		if err != nil {
			rollbackChanges(link, appliedChanges)
			return fmt.Errorf("failed to %v IP %v: %v", condition.TernaryOperator(isAdd, "add", "del"), ipCIDR, err)
		}

		appliedChanges[ipCIDR] = isAdd
	}

	return nil
}

func rollbackChanges(link netlink.Link, changes map[string]bool) {
	for ipCIDR, isAdd := range changes {
		addr, err := netlink.ParseAddr(ipCIDR)
		if err != nil {
			log.Printf("rollbackChanges parse addr err: %v\n", err)
			return
		}
		if isAdd {
			err = netlink.AddrDel(link, addr)
		} else {
			err = netlink.AddrAdd(link, addr)
		}
		if err != nil {
			log.Printf("failed to rollback %v IP %v: %v\n", condition.TernaryOperator(isAdd, "del", "add"), ipCIDR, err)
			return
		}
	}
}

func getIPsByMultiGroup(ipGroups []IPGroup) []string {
	ips := make([]string, 0)
	for _, group := range ipGroups {
		for _, floatingIP := range group.EgressFloatingIPs {
			ips = append(ips, floatingIP.IPCidr)
		}
		for _, unfloatingIP := range group.EgressUnfloatingIPs {
			ips = append(ips, unfloatingIP.IPCidr)
		}
	}
	return ips
}

func getAddIPs(newIPGroups, oldIPGroups []IPGroup) ([]string, error) {
	if len(newIPGroups) == 0 && len(oldIPGroups) == 0 {
		return nil, nil
	}

	newIPs := getIPsByMultiGroup(newIPGroups)

	if len(oldIPGroups) == 0 {
		return newIPs, nil
	}

	oldIPs := getIPsByMultiGroup(oldIPGroups)

	needAddIPs := slice.Difference(newIPs, oldIPs)
	return needAddIPs, nil
}

func AddAddrVlanIF(linkName, parentLinkName string, vlanID uint16, egressUnfloatingIP, egressFloatingIP []string) error {
	// vlan id 是 1 ~ 4096

	// 非浮动 ip 长度必须大于 0，浮动 ip 长度可以为 0

	// 如果有多个非浮动 ip，必须是相同的网段

	// 非浮动 ip 所在的网段，必须是未被使用过

	// 非浮动 ip 和浮动 ip 必须是同一个网段的

	// ip 应该都没有被使用

	// 添加到网卡

	// 如果有设置出口 IP，则要确保本网段的路由是使用此出口 IP

	// 把新增的信息记录到全局变量中
	return nil
}

// parseCIDR 解析IP地址和子网掩码
func parseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	return ip, ipnet, nil
}

// isSameSubnet 判断多个IP地址是否在同一个子网中
// func isSameSubnet(cidrs []string) (bool, error) {
// 	if len(cidrs) < 2 {
// 		return false, fmt.Errorf("at least two IP addresses are required")
// 	}
//
// 	_, firstIPNet, err := parseCIDR(cidrs[0])
// 	if err != nil {
// 		return false, err
// 	}
//
// 	for _, cidr := range cidrs[1:] {
// 		ip, _, err := parseCIDR(cidr)
// 		if err != nil {
// 			return false, err
// 		}
//
// 		if !firstIPNet.Contains(ip) {
// 			return false, nil
// 		}
// 	}
//
// 	return true, nil
// }

func IsIPUsed(ip string) (bool, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false, err
	}
	pinger.Count = 1
	pinger.Timeout = 500 * time.Millisecond
	if err := pinger.Run(); err != nil {
		return false, err
	}
	stats := pinger.Statistics()
	return stats.PacketsRecv > 0, nil
}
