package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/txn2/txeh"

	. "ztsdp"
)

type NetplanConfig struct {
	Network NetworkConfig `json:"network"`
}

type NetworkConfig struct {
	Version   int                       `json:"version"`
	Renderer  string                    `json:"renderer"`
	Ethernets map[string]EthernetConfig `json:"ethernets"`
}

type EthernetConfig struct {
	Addresses   []string          `json:"addresses"`
	DHCP4       bool              `json:"dhcp4"`
	DHCP6       bool              `json:"dhcp6"`
	Gateway4    string            `json:"gateway4"`
	Nameservers NameserversConfig `json:"nameservers"`
	WakeOnLan   bool              `json:"wakeonlan"`
}

type NameserversConfig struct {
	Addresses []string `json:"addresses"`
	Search    []string `json:"search"`
}

type InterfaceManager struct {
	InterfaceInfo map[string]InterfaceInfo
}

type InterfaceInfo struct {
	LastChangeTime        time.Time
	LastSendEventTime     time.Time
	IPPool                []string
	SPAPortPool           []string
	CommunicationPortPool []string
	VPNPortPool           []string
	ExpireTime            time.Duration
}

func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{}
}

func checkVPNSession() (bool, error) {
	type Params struct {
		HubName string `json:"HubName_str"`
	}

	type Request struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  Params `json:"params"`
	}

	vpnPassFile := "/var/lib/docker/volumes/geni_dkns_data/_data/sys/conf/sevpn.conf"
	f, err := os.ReadFile(vpnPassFile)
	if err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "sevpn file not founded.", Fields{"Error": err.Error()})
		return false, err
	}
	vpnPass := string(f[:])
	vpnPass = strings.Split(vpnPass, "=")[1]
	vpnPass = strings.TrimSpace(vpnPass)

	vpnConfFile := "/var/lib/docker/volumes/geni_dkns_data/_data/sys/conf/vpn_server.config"
	confFile, err := os.OpenFile(vpnConfFile, os.O_RDONLY, os.FileMode(0644))
	if err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "sevpn file not founded.", Fields{"Error": err.Error()})
		return false, err
	}
	defer confFile.Close()

	var hubName = ""
	scanner := bufio.NewScanner(confFile)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "string HubName") {
			temp := strings.TrimSpace(scanner.Text())
			hubName = strings.Split(temp, " ")[2]
		}
	}

	vpnServer := "127.0.0.1"
	vpnPort := "5555"

	url := fmt.Sprintf("https://%s:%s/api/", vpnServer, vpnPort)

	requestData := Request{
		JSONRPC: "2.0",
		ID:      "rpc_call_id",
		Method:  "EnumSession",
		Params: Params{
			HubName: hubName,
		},
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-VPNADMIN-PASSWORD", vpnPass)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	response := make(map[string]interface{})
	json.Unmarshal(body, &response)
	if res, ok := response["result"].(map[string]interface{}); ok {
		if sessionList, ok := res["SessionList"].([]interface{}); ok && len(sessionList) > 1 {
			Logger.Log(LOGTYPE_DEBUG, LOGID_SYSTEM, "The VPN session remains active.")
			return true, nil
		}

	}

	Logger.Log(LOGTYPE_DEBUG, LOGID_SYSTEM, "There is no VPN session.")
	return false, nil
}

func changeIP(oldIP string, newIP string) {
	Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Change IP.", Fields{"OldIP": oldIP, "NewIP": newIP})

	netPlan := NetplanConfig{}

	cmd := exec.Command("netplan", "get")
	netPlanResult, _ := cmd.CombinedOutput()

	err := yaml.Unmarshal(netPlanResult, &netPlan)
	if err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Unmarshalling error.", Fields{"Error": err.Error()})
	}

	etherName := ""

	for ethernet := range netPlan.Network.Ethernets {
		fmt.Printf("Current IP=%s", netPlan.Network.Ethernets[ethernet].Addresses)
		for _, address := range netPlan.Network.Ethernets[ethernet].Addresses {
			if strings.Split(address, "/")[0] == oldIP {
				etherName = ethernet
				break
			}
		}
	}

	setCmd := fmt.Sprintf("ethernets.%s.addresses=[%s/24]", etherName, newIP)
	fmt.Printf("%s\n", setCmd)
	cmd = exec.Command("netplan", "set", setCmd)
	err = cmd.Run()
	if err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Netplan set command error.", Fields{"Error": err.Error()})
	} else {
		cmd = exec.Command("netplan", "apply")
		err = cmd.Run()
		if err != nil {
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Netplan apply command error.", Fields{"Error": err.Error()})
		}

		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "change IP success.", Fields{"OldIP": oldIP, "NewIP": newIP})

		config.DeviceConfig.PrimaryIP = newIP
		writeConf()

		cmd = exec.Command("/usr/geni/compose.sh", "restart", "dkns")
		err = cmd.Run()
		if err != nil {
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "dkns restart failed.", Fields{"Error": err.Error()})
		} else {
			Logger.Log(LOGTYPE_DEBUG, LOGID_SYSTEM, "dkns restart successful.")
		}
	}
}

func changePort(kind string, oldPort string, newPort string) {
	Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Change Port.", Fields{"Type": kind, "OldPort": oldPort, "NewPort": newPort})

	switch kind {
	case "SPA":
		config.DeviceConfig.SpaPort, _ = strconv.Atoi(newPort)
	case "COMMUNICATION":
		config.DeviceConfig.CommunicationPort, _ = strconv.Atoi(newPort)
	case "VPN":
		config.DeviceConfig.VpnPort, _ = strconv.Atoi(newPort)
	}

	writeConf()
}

func (n *InterfaceManager) getIPByPool(alias string, currentIP string, currentIP2 string) string {
	var filteredPool []string

	// IPPool에서 현재 IP를 제외한 IP들을 필터링
	for _, ip := range n.InterfaceInfo[alias].IPPool {
		if ip != currentIP && ip != currentIP2 {
			filteredPool = append(filteredPool, ip)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := rnd.Intn(len(filteredPool))
	return filteredPool[randomIndex]
}

func (n *InterfaceManager) getSPAPortByPool(alias string, currentPort string) string {
	var filteredPool []string

	// SPA Port Pool에서 현재 port를 제외한 port들을 필터링
	for _, port := range n.InterfaceInfo[alias].SPAPortPool {
		if port != currentPort {
			filteredPool = append(filteredPool, port)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := rnd.Intn(len(filteredPool))
	return filteredPool[randomIndex]
}

func (n *InterfaceManager) getCommunicationPortByPool(alias string, currentPort string) string {
	var filteredPool []string

	// communication Port Pool에서 현재 port를 제외한 port들을 필터링
	for _, port := range n.InterfaceInfo[alias].CommunicationPortPool {
		if port != currentPort {
			filteredPool = append(filteredPool, port)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := rnd.Intn(len(filteredPool))
	return filteredPool[randomIndex]
}

func (n *InterfaceManager) getVPNPortByPool(alias string, currentPort string) string {
	var filteredPool []string

	// communication Port Pool에서 현재 port를 제외한 port들을 필터링
	for _, port := range n.InterfaceInfo[alias].VPNPortPool {
		if port != currentPort {
			filteredPool = append(filteredPool, port)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := rnd.Intn(len(filteredPool))
	return filteredPool[randomIndex]
}

func (n *InterfaceManager) expireCheck(force bool) {
	for i, gw := range config.GatewayConfig {
		if gw.PoolExpireTime > 0 {
			//if len(gw.IPPool) > 0 && gw.PoolExpireTime > 0 {
			inter, ok := n.InterfaceInfo[gw.Alias]
			if ok {
				now := time.Now()
				lastSendTime, err := redisClient.Get("LastSendIPChangeEventTime").Result()
				if err == redis.Nil {
					// 아직 실행된 적이 없다면 redis 에 현재시각 기록 후 리턴.
					//다음 주기에 실행되도록 한다.
					redisClient.Set("LastSendIPChangeEventTime", time.Now().Format(time.RFC3339), 0)
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "IP change check has never been run. Set it to run on the next cycle.", Fields{"Date": time.Now().Format(time.RFC3339)})
					return
				}
				parsedTime, err := time.Parse(time.RFC3339, lastSendTime)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Time parsing error.", Fields{"Error": err.Error()})
				}

				expire := parsedTime.Add(inter.ExpireTime)
				if force || now.After(expire) {
					var newIP string
					var newSPAPort string
					var newCommunicationPort string
					var newVPNPort string

					// domain 으로 전송하기 때문에 기존 도메인을 변경
					updateHostsFile(gw.Domain, gw.StandbyIp)

					// read ip/port by file
					if force {
						arg, err := os.ReadFile(IPPortChangerFilePath)
						if err != nil {
							Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Failed to read ipport.txt file.", Fields{"Error": err.Error()})
							return
						} else {
							args := strings.Split(string(arg), ",")
							if len(args) != 5 {
								Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Invalid argument ipport.txt file.", Fields{"Len": len(args)})
								return
							}
							alias := args[0]
							if alias != gw.Alias {
								continue
							}
							newIP = args[1]
							newSPAPort = args[2]
							newCommunicationPort = args[3]
							newVPNPort = args[4]
						}
					} else {
						newIP = n.getIPByPool(gw.Alias, gw.Ip, gw.StandbyIp)
						newSPAPort = n.getSPAPortByPool(gw.Alias, strconv.Itoa(gw.StandbySPAPort))
						newCommunicationPort = n.getCommunicationPortByPool(gw.Alias, strconv.Itoa(gw.StandbyCommPort))
						newVPNPort = n.getVPNPortByPool(gw.Alias, strconv.Itoa(gw.StandbyVPNPort))
					}

					ipData := IPJsonData{
						OldIP: gw.StandbyIp,
						NewIP: newIP,
					}
					spaData := SPAPortJsonData{
						OldPort: strconv.Itoa(gw.StandbySPAPort),
						NewPort: newSPAPort,
					}
					commData := CommunicationPortJsonData{
						OldPort: strconv.Itoa(gw.StandbyCommPort),
						NewPort: newCommunicationPort,
					}
					vpnData := VpnPortJsonData{
						OldPort: strconv.Itoa(gw.StandbyVPNPort),
						NewPort: newVPNPort,
					}

					packet := FillPacket(controllerMID, golbalSdpKey)

					Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "The IP has expired. IP change event was sent.", Fields{"OldIP": gw.StandbyIp, "NewIP": newIP})

					SendSpaPacket(packet, gw.Domain, gw.StandbySPAPort)
					time.Sleep(500 * time.Millisecond)
					err := sendIPPortChangeEvent(gw.Domain, gw.StandbyCommPort, ipData, spaData, commData, vpnData)
					redisClient.Set("LastSendIPChangeEventTime", time.Now().Format(time.RFC3339), 0)
					inter.LastSendEventTime = time.Now()
					n.InterfaceInfo[gw.Alias] = inter

					if err == nil {

						IptableManager.deleteFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "-s", gw.StandbyIp, "--sport", strconv.Itoa(gw.StandbyCommPort))
						IptableManager.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "-s", newIP, "--sport", newCommunicationPort)

						inter.LastChangeTime = time.Now()
						n.InterfaceInfo[gw.Alias] = inter

						// primary 에 new ip 를, standby 에 이전 primary ip를 할당한다.
						config.GatewayConfig[i].StandbyIp = gw.Ip
						config.GatewayConfig[i].Ip = newIP
						config.GatewayConfig[i].VpnPort, _ = strconv.Atoi(newVPNPort)
						config.GatewayConfig[i].SpaPort, _ = strconv.Atoi(newSPAPort)
						config.GatewayConfig[i].CommunicationPort, _ = strconv.Atoi(newCommunicationPort)
						config.GatewayConfig[i].StandbySPAPort = gw.SpaPort
						config.GatewayConfig[i].StandbyCommPort = gw.CommunicationPort
						config.GatewayConfig[i].StandbyVPNPort = gw.VpnPort
						updateGatewayInfo()

						err = updateHostsFile(gw.Domain, newIP)
						if err != nil {
							Logger.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "Hosts file update failed.", Fields{"Error": err.Error()})
						}

						writeConf()

						Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "Primary IP device has changed.", Fields{"StandbyIP": config.GatewayConfig[i].StandbyIp, "PrimaryIP": config.GatewayConfig[i].Ip})
					} else {
						Logger.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "IP change failed.", Fields{"Error": err.Error()})

						// 실패시 도메인 원상복구
						updateHostsFile(gw.Domain, gw.Ip)
					}
				}
			}
		}
	}
}

func updateHostsFile(domain string, newIP string) error {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "hosts file open failed.", Fields{"Error": err.Error()})
		return err
	}

	hosts.RemoveHost(domain)
	hosts.AddHost(newIP, domain)

	err = hosts.Save()
	if err != nil {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "hosts file save failed.", Fields{"Error": err.Error()})
	}

	Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "Hosts file updated.", Fields{"Domain": domain, "NewIP": newIP})

	//cmd := exec.Command("systemctl", "restart", "systemd-resolved")
	cmd := exec.Command("resolvectl", "flush-caches")
	err = cmd.Run()
	if err != nil {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "systemd-resolved command failed.", Fields{"Error": err.Error()})
	}

	return nil
}
