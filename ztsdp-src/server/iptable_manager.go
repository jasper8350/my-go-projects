package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"ztsdp"
	. "ztsdp"

	"github.com/coreos/go-iptables/iptables"
)

const (
	filterTable        = "filter"
	natTable           = "nat"
	inputChain         = "INPUT"
	preRoutingChain    = "PREROUTING"
	sdpInputChain      = "SDP-INPUT"
	sdpPreRoutingChain = "SDP-PREROUTING"
	dockerChain        = "DOCKER-USER"
	protoTCP           = "tcp"
	protoUDP           = "udp"
	targetAccept       = "ACCEPT"
	targetDrop         = "DROP"
)

type IPTableManager struct {
	iptablesManager   *iptables.IPTables     // iptables manager to manipulate the firewall rules
	udpPortTimers     map[string]*time.Timer // timer map to store the timers for each UDP port and source IP
	udpPortTimersLock sync.Mutex             // lock for concurrency safety of the timer map
	portTimeout       time.Duration
	vpnPortTimeout    time.Duration
	communicationPort string
	servicePortVPN    string
	keycloakPort      string
}

func getTapInterfaceUsingSensor() []string {
	var interfaces []string

	cmdStr := "cat /proc/nac/interface | awk -F '|' '{print $1}'|tail -n +2|sort|uniq"
	cmd := exec.Command("/bin/bash", "-c", cmdStr)
	cmdResult, _ := cmd.CombinedOutput()

	scanner := bufio.NewScanner(bytes.NewReader(cmdResult))
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" && strings.Contains(line, "tap") {
			interfaces = append(interfaces, strings.TrimSpace(line))
		}
	}
	return interfaces
}

func NewIPTableManager(iptablesManager *iptables.IPTables, portTimeout time.Duration, vpnPortTimeout time.Duration) *IPTableManager {
	// Create a new IPTableManager instance
	u := &IPTableManager{
		iptablesManager:   iptablesManager,
		udpPortTimers:     make(map[string]*time.Timer),
		portTimeout:       portTimeout,
		vpnPortTimeout:    vpnPortTimeout,
		communicationPort: strconv.Itoa(config.DeviceConfig.CommunicationPort),
		servicePortVPN:    strconv.Itoa(config.DeviceConfig.VpnPort),
		keycloakPort:      strconv.Itoa(config.KeycloakConfig.HostPort),
	}

	u.iptablesManager.ClearChain("filter", sdpInputChain)
	u.iptablesManager.ClearChain("nat", sdpPreRoutingChain)

	u.createFilterRule(sdpInputChain, targetAccept, "-i", "lo")

	u.createFilterRule(sdpInputChain, targetAccept, "-i", "br-sdp0")

	u.createFilterRule(sdpInputChain, targetAccept, "-p", protoUDP, "--sport", "53")

	u.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "--sport", "53")

	centerIP, _ := ExtractIPPortString(config.DeviceConfig.PolicyServerIP)
	u.createFilterRule(sdpInputChain, targetAccept, "-s", centerIP)

	u.createFilterRule(sdpInputChain, targetAccept, "-s", config.DeviceConfig.SshAllowedIP, "-p", "tcp", "--dport", "22")

	u.createFilterRule(sdpInputChain, targetAccept, "-p", protoUDP, "--dport", strconv.Itoa(config.DeviceConfig.SpaPort))

	if isController() {
		u.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "--sport", "8443")

		for _, gw := range config.GatewayConfig {
			u.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "-s", gw.Ip, "--sport", strconv.Itoa(gw.CommunicationPort))
			if gw.StandbyCommPort != 0 {
				u.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "-s", gw.StandbyIp, "--sport", strconv.Itoa(gw.StandbyCommPort))
			}
		}

		u.createFilterRule(dockerChain, targetDrop, "-p", protoTCP, "-m", "conntrack", "--ctorigdstport", strconv.Itoa(config.KeycloakConfig.HostPort))

		u.createFilterRule(dockerChain, targetAccept, "-p", protoTCP, "-m", "conntrack", "--ctorigsrc", "127.0.0.1", "--ctorigdstport", strconv.Itoa(config.KeycloakConfig.HostPort))

		u.createFilterRule(dockerChain, targetAccept, "-p", protoTCP, "-m", "conntrack", "--ctorigsrc", config.DeviceConfig.SshAllowedIP, "--ctorigdstport", strconv.Itoa(config.KeycloakConfig.HostPort))

	} else {
		// 센서에서 사용되는 인터페이스는 허용
		interfaces := getTapInterfaceUsingSensor()
		for _, ifc := range interfaces {
			u.createFilterRule(sdpInputChain, targetAccept, "-i", ifc)
		}

		dst := fmt.Sprintf("%s:1194", config.DeviceConfig.PrimaryIP)
		u.createRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", strconv.Itoa(config.DeviceConfig.VpnPort), "-j", "DNAT", "--to-destination", dst)

		u.createRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", strconv.Itoa(config.DeviceConfig.VpnPort), "-j", "MARK", "--set-mark", "111")

		u.createFilterRule(sdpInputChain, targetAccept, "-p", protoTCP, "--dport", "1194", "-m", "state", "--state", "RELATED,ESTABLISHED")

		u.createFilterRule(sdpInputChain, targetAccept, "-s", config.DeviceConfig.ControllerIP, "-p", protoUDP, "--dport", strconv.Itoa(config.DeviceConfig.SpaPort))
	}
	u.createFilterRule(sdpInputChain, targetAccept, "-s", "127.0.0.1")

	u.createFilterRule(inputChain, sdpInputChain)
	u.createRoutingRule(preRoutingChain, "-j", sdpPreRoutingChain)

	if err := u.iptablesManager.ChangePolicy(filterTable, inputChain, targetDrop); err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_IPTABLE, "Failed to change INPUT default rule.", Fields{"Error": err.Error()})
	} else {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_IPTABLE, "Changed INPUT default rule.", Fields{"Rule": "DROP"})
	}

	return u
}

func parseRuleSpec(ruleSpec ...string) map[string]string {
	parsed := make(map[string]string)

	for i := 0; i < len(ruleSpec); i++ {
		if strings.HasPrefix(ruleSpec[i], "-") && i+1 < len(ruleSpec) {
			parsed[ruleSpec[i]] = ruleSpec[i+1]
			i++
		}
	}

	return parsed
}

func makeLogMsg(chain string, ruleSpec ...string) string {
	parsedRules := parseRuleSpec(ruleSpec...)
	logMsg := ""

	logMsg = fmt.Sprintf("Chain=%s", chain)

	if protocol, exists := parsedRules["-p"]; exists {
		logMsg += fmt.Sprintf(" Protocol=%s", protocol)
	}
	if inter, exists := parsedRules["-i"]; exists {
		logMsg += fmt.Sprintf(" Interface=%s", inter)
	}
	if srcIP, exists := parsedRules["-s"]; exists {
		logMsg += fmt.Sprintf(" SrcIP=%s", srcIP)
	}
	if dstIP, exists := parsedRules["-d"]; exists {
		logMsg += fmt.Sprintf(" dstIP=%s", dstIP)
	}
	if dstPort, exists := parsedRules["--dport"]; exists {
		logMsg += fmt.Sprintf(" DstPort=%s", dstPort)
	}
	if srcPort, exists := parsedRules["--sport"]; exists {
		logMsg += fmt.Sprintf(" SrcPort=%s", srcPort)
	}
	if ctOrigSrcIP, exists := parsedRules["--ctorigsrc"]; exists {
		logMsg += fmt.Sprintf(" CtOrigSrc=%s", ctOrigSrcIP)
	}
	if ctOrigDstPort, exists := parsedRules["--ctorigdstport"]; exists {
		logMsg += fmt.Sprintf(" CtOrigDstPort=%s", ctOrigDstPort)
	}
	if rule, exists := parsedRules["-j"]; exists {
		logMsg += fmt.Sprintf(" Rule=%s", rule)
	}

	return logMsg
}

func (u *IPTableManager) createRoutingRule(iptablesChain string, ruleSpec ...string) error {
	logMsg := makeLogMsg(iptablesChain, ruleSpec...)

	if err := u.iptablesManager.InsertUnique(natTable, iptablesChain, 1, ruleSpec...); err != nil {
		ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Failed Creating iptables routing rule. "+logMsg)
		return err
	}

	ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Created iptables routing rule. "+logMsg)
	return nil
}

func (u *IPTableManager) deleteRoutingRule(iptablesChain string, ruleSpec ...string) error {
	logMsg := makeLogMsg(iptablesChain, ruleSpec...)

	if err := u.iptablesManager.Delete(natTable, iptablesChain, ruleSpec...); err != nil {
		ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Failed deleting iptables routing rule. "+logMsg)
	}

	ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "deleted iptables routing rule. "+logMsg)
	return nil
}

func (u *IPTableManager) createFilterRule(iptablesChain string, rule string, ruleSpec ...string) error {
	ruleSpec = append(ruleSpec, "-j", rule)

	logMsg := makeLogMsg(iptablesChain, ruleSpec...)

	// If not, append a new rule to open the UDP port using iptables manager
	if err := u.iptablesManager.InsertUnique(filterTable, iptablesChain, 1, ruleSpec...); err != nil {
		ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Failed Creating iptables rule. "+logMsg)
		return err
	}

	ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Created iptables rule. "+logMsg)
	return nil
}

func (u *IPTableManager) deleteFilterRule(iptablesChain string, rule string, ruleSpec ...string) error {
	ruleSpec = append(ruleSpec, "-j", rule)

	logMsg := makeLogMsg(iptablesChain, ruleSpec...)

	if err := u.iptablesManager.Delete(filterTable, iptablesChain, ruleSpec...); err != nil {
		ztsdp.Logger.LogWithFields(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Failed Deleting iptables rule. "+logMsg, Fields{"Error": err.Error()})
		return err
	}
	ztsdp.Logger.Log(ztsdp.LOGTYPE_DEBUG, ztsdp.LOGID_IPTABLE, "Deleted iptables rule. "+logMsg)
	return nil
}

func (u *IPTableManager) openAndSchedulePort(sourceIP string, accessVPN bool, iptableChain string, targetPort int, protocol string) {

	var port string
	var portTimeout time.Duration

	// Lock the timer map for concurrency safety
	u.udpPortTimersLock.Lock()
	defer u.udpPortTimersLock.Unlock()

	port = strconv.Itoa(targetPort)

	if accessVPN {
		portTimeout = u.vpnPortTimeout
	} else {
		portTimeout = u.portTimeout
	}

	// Generate a timer key with the format "communicationPort-sourceIP"
	timerKey := port + "-" + sourceIP

	// If there is an existing timer for the same key, stop it
	if existingTimer, exists := u.udpPortTimers[timerKey]; exists {
		existingTimer.Stop()
	}

	var spec []string

	if isController() {
		spec = append(spec, "-p", protoTCP, "-m", "conntrack", "--ctorigsrc", sourceIP, "--ctorigdstport", port)
		u.createFilterRule(dockerChain, targetAccept, spec...)
	} else {
		if accessVPN {
			spec = append(spec, "-m", "mark", "--mark", "111", "-p", protocol, "--dport", port, "-s", sourceIP)
			if err := u.createFilterRule(sdpInputChain, targetAccept, spec...); err != nil {
				log.Println("Failed to open Service port:", err)
				return
			}
		} else {
			spec = append(spec, "-p", protoTCP, "--dport", port, "-s", sourceIP)
			if err := u.createFilterRule(sdpInputChain, targetAccept, spec...); err != nil {
				log.Println("Failed to open Service port:", err)
				return
			}
		}
	}

	// Schedule a function to close the UDP port after the duration using time.AfterFunc
	u.udpPortTimers[timerKey] = time.AfterFunc(portTimeout, func() {
		u.closePort(sourceIP, port, spec...)
	})
}

func (u *IPTableManager) closePort(sourceIP string, servicePort string, spec ...string) {
	// Lock the timer map for concurrency safety
	u.udpPortTimersLock.Lock()
	defer u.udpPortTimersLock.Unlock()

	// Generate a timer key with the format "communicationPort-sourceIP"
	timerKey := servicePort + "-" + sourceIP

	// If there is an existing timer for the same key, stop it and delete it from the timer map
	if existingTimer, exists := u.udpPortTimers[timerKey]; exists {
		existingTimer.Stop()
		delete(u.udpPortTimers, timerKey)

		if isController() {
			u.deleteFilterRule(dockerChain, targetAccept, spec...)
		} else {
			// Delete the iptables rule to close the UDP port for the source IP
			u.deleteFilterRule(sdpInputChain, targetAccept, spec...)
		}
	}
}
