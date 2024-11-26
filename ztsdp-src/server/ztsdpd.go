package main

import (
	"crypto/hmac"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-redis/redis"
	"gopkg.in/yaml.v3"

	// genians
	. "ztsdp"
)

// Struct to hold extracted packet data
type ExtractedPacket struct {
	MachineID string
	Nonce     uint16
	Timestamp uint64
	SourceIP  net.IP
	OTPValue  string
	HMACValue []byte
}

const (
	ZTSDPD_CONF = "/etc/ztsdpd.yaml"
)

var (
	// args
	golbalSdpKey  string
	controllerMID string

	keycloakManager *string

	redisClient *redis.Client

	authManager *AuthManager

	hmacAuthManager *HmacAuthManager

	IptableManager *IPTableManager

	config Config

	interfaceManager *InterfaceManager
)

type NacAPIResponse struct {
	Code      int          `json:"code"`
	Message   string       `json:"message"`
	Parameter interface{}  `json:"parameter"` // null 값을 허용
	Data      []DeviceInfo `json:"data"`
}

type DeviceInfo struct {
	NI_AUTHTIME []int `json:"NI_AUTHTIME"`
}

func extractPacket(packet []byte) (ExtractedPacket, error) {

	if len(packet) != (MachineIDSize + NonceSize + TimestampSize + SourceIPSize + OTPSize + HMACSize) {
		return ExtractedPacket{}, fmt.Errorf("Invalid length: %d", len(packet))
	}

	// Slice and convert each field from the packet and assign them to an ExtractedPacket struct
	return ExtractedPacket{
		MachineID: strings.TrimRight(string(packet[:MachineIDSize]), "\x00"),                                                                       // Trim the trailing null bytes from the machine ID
		Nonce:     binary.BigEndian.Uint16(packet[MachineIDSize : MachineIDSize+NonceSize]),                                                        // Convert the nonce from big endian to uint16
		Timestamp: binary.BigEndian.Uint64(packet[MachineIDSize+NonceSize : MachineIDSize+NonceSize+TimestampSize]),                                // Convert the timestamp from big endian to uint64
		SourceIP:  net.IP(packet[MachineIDSize+NonceSize+TimestampSize : MachineIDSize+NonceSize+TimestampSize+SourceIPSize]),                      // Convert the source IP to net.IP type
		OTPValue:  string(packet[MachineIDSize+NonceSize+TimestampSize+SourceIPSize : MachineIDSize+NonceSize+TimestampSize+SourceIPSize+OTPSize]), // Convert the OTP to string
		HMACValue: packet[len(packet)-HMACSize:],                                                                                                   // Slice the last HMACSize bytes from the packet
	}, nil
}

// verifyHMAC verifies the HMAC value using the SDP key and the extracted fields and returns a boolean value.
func verifyHMAC(sdpKey string, machineID string, nonce uint16, timestamp uint64, sourceIP net.IP, otpValue string, hmacValue []byte) bool {

	// Generate an HMAC using the ztsdp package
	hmacCalculated := GenerateHMAC(machineID, sdpKey, nonce, timestamp, sourceIP, otpValue)

	// Compare the generated HMAC with the input HMAC
	if !hmac.Equal(hmacValue, hmacCalculated) {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Mismatch HMAC.", Fields{"HMAC": hmacCalculated, "VALUE": hmacValue, "SDPKey": sdpKey, "MachineID": machineID})
		return false
	}

	// If the HMACs match, return true
	return true
}

// verifyOTP verifies the OTP value using the SDP key and the machine ID and returns a boolean value.
func verifyOTP(sdpKey string, machineID string, otpValue string) bool {

	// Generate an OTP using the ztsdp package
	otpCalculated := GenerateOTP(machineID, sdpKey)

	// Compare the generated OTP with the input OTP
	if otpCalculated != otpValue {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Mismatch TOTP.", Fields{"OTPCalc": otpCalculated, "VALUE": otpValue, "SDPKey": sdpKey, "MachineID": machineID})
		return false
	}

	// If the OTPs match, return true
	return true
}

// Function to verify the entire packet
func verifyPacket(packet []byte) bool {

	// Declare a variable for the SDP key
	var sdpKey string
	var sdpSourceIP string
	var err error

	// Extract the packet
	extractedPacket, err := extractPacket(packet)

	if err != nil {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Extract packet failed.", Fields{"Error": err.Error()})
		return false
	}

	sdpKey = golbalSdpKey

	if isController() {
		// If the role is controller, check the machine ID in Redis and get the fixed SDP key
		users, err := getUsersWithMID(extractedPacket.MachineID)
		if len(users) <= 0 || err != nil {
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Failed getting user with MID", Fields{"SrcIP": extractedPacket.SourceIP})
			return false
		}
	} else {
		if controllerMID != extractedPacket.MachineID {
			if !authManager.isDataExists(extractedPacket.MachineID) {
				Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Unknown machineID in dataMap", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})
				return false
			}
			sdpKey, err = authManager.getSdpKey(extractedPacket.MachineID)
			if err != nil {
				Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Failed to get sdpKey", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})
				return false
			}
			sdpSourceIP, err = authManager.getSdpSourceIP(extractedPacket.MachineID)
			if err != nil {
				// Handle the error
				Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Failed to get sdpSourceIP", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})

				return false
			}
			if sdpSourceIP != extractedPacket.SourceIP.String() {
				Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "This IP does not authorized.", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})
			}

			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Authed this machine", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})
		}
	}

	// Verify the HMAC value using the SDP key and the extracted fields
	if !verifyHMAC(
		sdpKey,
		extractedPacket.MachineID,
		extractedPacket.Nonce,
		extractedPacket.Timestamp,
		extractedPacket.SourceIP,
		extractedPacket.OTPValue,
		extractedPacket.HMACValue,
	) {
		return false
	}

	// Verify the OTP value using the SDP key and the machine ID
	if !verifyOTP(
		sdpKey,
		extractedPacket.MachineID,
		extractedPacket.OTPValue,
	) {
		return false
	}

	// If all verifications are successful, return true
	return true
}

// printPacket prints the extracted SPA packet data to the log.
func printPacket(extracted ExtractedPacket) {
	// Format the timestamp to a human-readable format
	timestamp := time.Unix(int64(extracted.Timestamp), 0).Format("2006-01-02 15:04:05")

	// Print the machine ID, nonce, timestamp, source IP, HMAC value, and OTP value to the log
	Logger.Logf(LOGTYPE_DEBUG, LOGID_EVENT, "Received SPA. MachineID=%s Nonce=%d Timestamp=%s SourceIP=%s HMAC=%x OTP=%s",
		extracted.MachineID, extracted.Nonce, timestamp, extracted.SourceIP, extracted.HMACValue, extracted.OTPValue)
}

// Function to set the SDP key from Redis or generate a random one
func setSdpKeyInRedis() error {
	// Get the SDP key from Redis using the key "SDPKEY"
	key, err := redisClient.Get("SDPKEY").Result()
	if err != nil {
		// If there is an error, return it
		log.Println("Failed to get SDPKEY from Redis:", err)
		return err
	}

	// Set the global variable golbalSdpKey to the key
	golbalSdpKey = key

	key, err = redisClient.Get("SDPCONTROLLER").Result()
	if err != nil {
		// If there is an error, return it
		log.Println("No SDPCONTROLLER in Redis:", err)
		return nil
	}

	controllerMID = key

	return nil
}

// Function to process a received packet
func processSpaPacket(packet []byte, srcAddr net.Addr) {

	// Extract the packet
	extractedPacket, err := extractPacket(packet)

	if err != nil {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Abnormal SPA packet.", Fields{"Error": err.Error()})
		return
	}

	printPacket(extractedPacket)

	hmacHex := fmt.Sprintf("%X", extractedPacket.HMACValue)

	if hmacAuthManager.isDataExists(hmacHex) {
		log.Printf("HMAC already cached. HMAC=%s", hmacHex)
		return
	}

	sourceIP := extractedPacket.SourceIP
	udpAddr, _ := srcAddr.(*net.UDPAddr)

	if !udpAddr.IP.Equal(sourceIP) {
		if !udpAddr.IP.Equal(net.ParseIP("127.0.0.1")) {
			Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "NAT IP detected.", Fields{"SrcIP": sourceIP, "Header IP": udpAddr.IP})
			sourceIP = udpAddr.IP
		}
	}

	if verifyPacket(packet) {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "SPA Packet Verification OK.", Fields{"SrcIP": sourceIP})

		hmacAuthManager.storeData(hmacHex, HmacAuthData{
			SourceIP:  sourceIP,
			Timestamp: extractedPacket.Timestamp,
		})

		var users []User
		if isController() {
			users, err = getUsersWithMID(extractedPacket.MachineID)
			if err != nil {
				Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Get user failed.", Fields{"MID": extractedPacket.MachineID, "Error": err.Error()})
				return
			}

			if len(users) <= 0 {
				Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Not found user.", Fields{"MID": extractedPacket.MachineID})
				return
			}

			// 센터 정보와 api key 정보가 존재하면 센터로부터 인증확인을 받는다.
			if config.DeviceConfig.PolicyServerIP != "" && config.DeviceConfig.PolicyServerAPIKey != "" {
				url := fmt.Sprintf("https://%s/mc2/rest/nac/deviceinfo/%s?type=NSRINFO&apiKey=%s", config.DeviceConfig.PolicyServerIP, extractedPacket.MachineID, config.DeviceConfig.PolicyServerAPIKey)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Failed to create new request.", Fields{"Error": err.Error()})
					return
				}
				req.Header.Add("accept", "application/json;charset=UTF-8")

				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
					Timeout: 3 * time.Second,
				}

				resp, err := client.Do(req)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Processing of client's request failed", Fields{"Error": err.Error()})
					return
				}
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Error reading response body.", Fields{"Error": err.Error()})
					return
				}

				var response NacAPIResponse
				err = json.Unmarshal(body, &response)
				if response.Code == http.StatusOK && len(response.Data) > 0 {
					layout := "2006-01-02 15:04:05"
					authTimeStr := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
						response.Data[0].NI_AUTHTIME[0], response.Data[0].NI_AUTHTIME[1], response.Data[0].NI_AUTHTIME[2],
						response.Data[0].NI_AUTHTIME[3], response.Data[0].NI_AUTHTIME[4], response.Data[0].NI_AUTHTIME[5])
					authTime, _ := time.Parse(layout, authTimeStr)
					if authTime.Before(time.Now()) {
						Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "The time to authenticate has expired.", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP, "AuthTime": authTime.String()})
						return
					} else {
						Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_EVENT, "The authentication time has been confirmed by policy server.", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP})
					}
				} else {
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Authentication API check failed.", Fields{"MID": extractedPacket.MachineID, "SrcIP": extractedPacket.SourceIP, "Code": strconv.Itoa(response.Code), " Message": response.Message})
					return
				}
			}
		}

		if isGateway() {
			if controllerMID == extractedPacket.MachineID {
				IptableManager.openAndSchedulePort(sourceIP.String(), false, "INPUT", config.DeviceConfig.CommunicationPort, "tcp")
			} else {
				// 내부적으로 사용되는 vpn 포트는 항상 1194.
				IptableManager.openAndSchedulePort(sourceIP.String(), true, "INPUT", 1194, "tcp")
			}
		} else {
			IptableManager.openAndSchedulePort(sourceIP.String(), false, "FORWARD", config.KeycloakConfig.HostPort, "tcp")
		}

		if isController() {

			// generate dynamic secret
			secret := make([]string, len(config.GatewayConfig))

			for idx, gateway := range config.GatewayConfig {
				bytes := make([]byte, 16)
				rand.Read(bytes)
				secret[idx] = hex.EncodeToString(bytes)

				err = updateUserSecret(users[0].ID, extractedPacket.MachineID, secret[idx], fmt.Sprintf("gw%d-sky", idx+1))
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_EVENT, "Update user secret failed.", Fields{"MID": extractedPacket.MachineID, "User": users[0].Username})
					return
				} else {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_EVENT, "Update user secret.", Fields{"MID": extractedPacket.MachineID, "User": users[0].Username})
				}

				packet := FillPacket(controllerMID, golbalSdpKey)
				SendSpaPacket(packet, gateway.Domain, gateway.SpaPort)
			}

			time.Sleep(500 * time.Millisecond)

			for idx, gateway := range config.GatewayConfig {
				sendAuthEvent(gateway.Domain, gateway.CommunicationPort, sourceIP.String(), extractedPacket.MachineID, secret[idx])
			}
		}
	} else {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "SPA Packet Verification Fail.", Fields{"SrcIP": sourceIP})
	}

	//hmacAuthManager.printDataMap()
}

// parseFlags parses the command-line flags and returns the spa port.
func parseFlags() {
	//role = flag.String("role", "controller", "daemon role: controller or gw")
	flag.String("role", "controller", "daemon role: controller or gw")
	flag.String("spa-port", "50001", "port number to listen for SPA packets")
	flag.String("service-port", "8443", "port number to listen for service requests")
	flag.String("service-port-vpn", "1194", "port number to listen for vpn service requests")
	//gatewayIP := flag.String("gateway-ip", "192.168.0.1, 192.168.0.2, ...", "gateway ip address to send spa packet")
	//gatewayPort := flag.Int("gateway-port", 50003, "gateway port number to send spa packet")
	//gatewayServicePort := flag.String("gateway-service-port", "50004", "gateway port number to send data packet")
	flag.String("port-timeout", "10", "timeout duration for opening service port")
	flag.String("vpn-port-timeout", "60", "timeout duration for opening vpn service port")
	//keycloakManager = flag.String("keycloak-manager", "path/kcadmin.sh", "path to the keycloak manager file")
	flag.String("policy-server-ip", "127.0.0.1", "policy server ip address to accept packet")
	flag.String("ssh-access-user-ip", "127.0.0.1", "ssh access user ip address to accept packet")

	flag.Parse()

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "role":
			config.DeviceConfig.Role = f.Value.String()
		case "spa-port":
			config.DeviceConfig.SpaPort, _ = strconv.Atoi(f.Value.String())
		case "service-port":
			config.DeviceConfig.CommunicationPort, _ = strconv.Atoi(f.Value.String())
		case "service-port-vpn":
			config.DeviceConfig.VpnPort, _ = strconv.Atoi(f.Value.String())
		case "port-timeout":
			config.DeviceConfig.PortTimeout, _ = strconv.Atoi(f.Value.String())
		case "vpn-port-timeout":
			config.DeviceConfig.VPNPortTimeout, _ = strconv.Atoi(f.Value.String())
		case "policy-server-ip":
			config.DeviceConfig.PolicyServerIP = f.Value.String()
		case "ssh-access-user-ip":
			config.DeviceConfig.SshAllowedIP = f.Value.String()
		}
	})
}

// sets the SDP key secret
func setSdpKeys() {
	if err := setSdpKeyInRedis(); err != nil {
		log.Println("Failed to initialize SDP key secret:", err)
		os.Exit(1)
	}
}

// printOptions prints the configured options in a neat format using fmt.Printf.
func printOptions() {
	if isController() {
		Logger.Logf(LOGTYPE_INFO, LOGID_SYSTEM, "Role=%s SPAPort=%d CommunicationPort=%d", config.DeviceConfig.Role, config.DeviceConfig.SpaPort, config.DeviceConfig.CommunicationPort)
	} else {
		Logger.Logf(LOGTYPE_INFO, LOGID_SYSTEM, "Role=%s SPAPort=%d CommunicationPort=%d VPNPort=%d",
			config.DeviceConfig.Role, config.DeviceConfig.SpaPort, config.DeviceConfig.CommunicationPort, config.DeviceConfig.VpnPort)
	}
}

// createServerSocket creates a UDP server socket and returns it.
func createServerSocket(spaPort string) net.PacketConn {
	serverSocket, err := net.ListenPacket("udp", ":"+spaPort)
	if err != nil {
		log.Println("Failed to create UDP server:", err)
		return nil
	}
	return serverSocket
}

// processSpaPackets reads and processes SPA packets from the server socket in a loop.
func processSpaPackets(serverSocket net.PacketConn) {
	for {
		buffer := make([]byte, 1024)
		n, srcAddr, err := serverSocket.ReadFrom(buffer)
		if err != nil {
			log.Println("Failed to read UDP packet:", err)
			continue
		}

		go processSpaPacket(buffer[:n], srcAddr)
	}
}

func parseIPPool(pool string) ([]string, error) {
	var ips []string

	// 여러 IP 풀을 쉼표로 구분하여 분리
	ranges := strings.Split(pool, ",")

	for _, r := range ranges {
		if strings.Contains(r, "-") {
			// IP 범위일 경우
			ipRange := strings.Split(r, "-")

			startIP := ipRange[0]
			endPart := ipRange[1]

			// IP 주소를 '.' 기준으로 분리
			startIPParts := strings.Split(startIP, ".")

			// IP 주소의 마지막 부분을 정수로 변환
			startLastPart, err := strconv.Atoi(startIPParts[3])
			if err != nil {
				return nil, err
			}
			endLastPart, err := strconv.Atoi(endPart)
			if err != nil {
				return nil, err
			}

			// IP 범위 생성
			for i := startLastPart; i <= endLastPart; i++ {
				currentIP := fmt.Sprintf("%s.%d", strings.Join(startIPParts[:3], "."), i)
				ips = append(ips, currentIP)
			}
		} else {
			// IP 범위가 아닌 경우 (단일 IP)
			ips = append(ips, r)
		}
	}

	return ips, nil
}

func parsePortPool(pool string) ([]string, error) {
	var ports []string

	// 여러 port 풀을 쉼표로 구분하여 분리
	ranges := strings.Split(pool, ",")

	for _, r := range ranges {
		if strings.Contains(r, "-") {
			// 범위일 경우
			portRange := strings.Split(r, "-")

			startPort, _ := strconv.Atoi(portRange[0])
			endPort, _ := strconv.Atoi(portRange[1])

			// IP 범위 생성
			for i := startPort; i <= endPort; i++ {
				ports = append(ports, strconv.Itoa(i))
			}
		} else {
			// IP 범위가 아닌 경우 (단일 IP)
			ports = append(ports, r)
		}
	}

	return ports, nil
}

func init() {
	// Create a new auth manager
	authManager = NewAuthManager()

	// Create a new hmac auth manager
	hmacAuthManager = NewHmacAuthManager()

	// Create and connect a Redis client
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	if _, err := os.Stat(ZTSDPD_CONF); err == nil {
		file, _ := os.ReadFile(ZTSDPD_CONF)
		err = yaml.Unmarshal(file, &config)
		if err != nil {
			fmt.Printf(err.Error())
		}

		if config.DeviceConfig.PortTimeout == 0 {
			config.DeviceConfig.PortTimeout = 10
		}
		if config.DeviceConfig.VPNPortTimeout == 0 {
			config.DeviceConfig.VPNPortTimeout = 60
		}

		NewLogger(isController(), config.DatabaseConfig.DbAdminId, config.DatabaseConfig.DbAdminPassword)

		Logger.LogInit()
		Logger.Log(LOGTYPE_INFO, LOGID_SYSTEM, "ztsdp daemon started.")

		for idx, gw := range config.GatewayConfig {
			if gw.Alias == "" {
				config.GatewayConfig[idx].Alias = fmt.Sprintf("none%d", idx+1)
			}
		}

		if config.DeviceConfig.SpaGlobalSecret != "" {
			redisClient.Set("SDPKEY", config.DeviceConfig.SpaGlobalSecret, 0)
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Set SDPKEY in redis.", Fields{"SDPKEY": config.DeviceConfig.SpaGlobalSecret})
		}
		if config.DeviceConfig.ControllerUUID != "" {
			redisClient.Set("SDPCONTROLLER", config.DeviceConfig.ControllerUUID, 0)
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Set SDPCONTROLLER in redis.", Fields{"SDPCONTROLLER": config.DeviceConfig.ControllerUUID})
		}

		if isController() {
			createRealm()
			createClient()
			createClientScope()
			updateGatewayInfo()
			createUserProfile("MID")

			for idx, _ := range config.GatewayConfig {
				createUserProfile(fmt.Sprintf("gw%d-sky", idx+1))
			}

			interfaceManager = NewInterfaceManager()
			interfaceManager.InterfaceInfo = make(map[string]InterfaceInfo)
			info := InterfaceInfo{}

			for _, gw := range config.GatewayConfig {
				// parse ip pool
				pools, err := parseIPPool(gw.IPPool)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "IP pool parsing failed.", Fields{"Error": err.Error()})
				}
				info.IPPool = pools
				info.ExpireTime = time.Duration(gw.PoolExpireTime) * time.Minute

				err = updateHostsFile(gw.Domain, gw.Ip)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "Hosts file update failed.", Fields{"Error": err.Error()})
				}

				// parse SPA port pool
				pools, err = parsePortPool(gw.SPAPortPool)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "SPA port pool parsing failed.", Fields{"Error": err.Error()})
				}
				info.SPAPortPool = pools

				// parse communication port pool
				pools, err = parsePortPool(gw.CommunicationPortPool)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "Communication port pool parsing failed.", Fields{"Error": err.Error()})
				}
				info.CommunicationPortPool = pools

				// parse communication port pool
				pools, err = parsePortPool(gw.VPNPortPool)
				if err != nil {
					Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "VPN port pool parsing failed.", Fields{"Error": err.Error()})
				}
				info.VPNPortPool = pools

				interfaceManager.InterfaceInfo[gw.Alias] = info
			}
		}
	} else {
		log.Fatalf("%s file not found.", ZTSDPD_CONF)
	}
}

func isController() bool {
	if config.DeviceConfig.Role == "controller" {
		return true
	}
	return false
}

func isGateway() bool {
	if config.DeviceConfig.Role == "gateway" {
		return true
	}
	return false
}

func checkIPChange() {
	for {
		interfaceManager.expireCheck(false)
		time.Sleep(1 * time.Minute)
	}
}

func writeConf() {
	conf, err := yaml.Marshal(config)
	if err == nil {
		err = os.WriteFile(ZTSDPD_CONF, conf, 0644)
		if err != nil {
			Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "config file write failed.", Fields{"Error": err.Error()})
		}
	} else {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_SYSTEM, "config marshaling error", Fields{"Error": err.Error()})
	}
}

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for {
			sig := <-sigs
			Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "ztsdpd daemon received signal.", Fields{"SIGNAL": sig})

			switch sig {
			case syscall.SIGTERM:
				os.Exit(1)
			case syscall.SIGINT:
				os.Exit(1)
			case syscall.SIGUSR1:
				Logger.Log(LOGTYPE_INFO, LOGID_SYSTEM, "ztsdpd daemon received ip/port change signal.")
				interfaceManager.expireCheck(true)
			}
		}
	}()

	//defer database.Close()

	// Parse flags
	parseFlags()

	// Create a new iptables manager
	iptablesManager, err := iptables.New()
	if err != nil {
		Logger.LogWithFields(LOGTYPE_FATAL, LOGID_SYSTEM, "Failed to create iptables manager.", Fields{"ERROR": err.Error()})
	}

	// Create a new UDP port manager with the iptables manager
	IptableManager = NewIPTableManager(iptablesManager, time.Duration(config.DeviceConfig.PortTimeout)*time.Second, time.Duration(config.DeviceConfig.VPNPortTimeout)*time.Second)

	// Set SDP keys : Preshared Secret & machineID
	setSdpKeys()

	// Print the configured options
	printOptions()

	// Create UDP server socket
	serverSocket := createServerSocket(strconv.Itoa(config.DeviceConfig.SpaPort))
	defer serverSocket.Close()

	if isGateway() {
		go startWSS(strconv.Itoa(config.DeviceConfig.CommunicationPort))
	}

	if isController() {
		go checkIPChange()
	}

	// Process SPA packets in a loop
	processSpaPackets(serverSocket)
}
