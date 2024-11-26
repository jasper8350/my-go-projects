package ztsdp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crypt "crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
)

// Constants for packet field sizes
const (
	MachineIDSize = 36
	NonceSize     = 2
	TimestampSize = 8
	SourceIPSize  = 4
	OTPSize       = 6
	HMACSize      = 32

	AES_KEY = "0b6a678ea91a2c8f5f22b738ccba40e2"

	IPPortChangerFilePath = "/ztsdp/ipport.txt"
)

type DeviceConfig struct {
	Role               string `yaml:"role"`
	PrimaryIP          string `yaml:"primaryIP"`
	CommunicationPort  int    `yaml:"communicationPort"`
	SpaPort            int    `yaml:"spaPort"`
	VpnPort            int    `yaml:"vpnPort"`
	PolicyServerIP     string `yaml:"policyServerIp"`
	SshAllowedIP       string `yaml:"sshAllowedIp"`
	SpaGlobalSecret    string `yaml:"spaGlobalSecret"`
	ControllerIP       string `yaml:"controllerIP"`
	ControllerUUID     string `yaml:"controllerUUID"`
	PolicyServerAPIKey string `yaml:"policyServerAPIKey"`
	PortTimeout        int    `yaml:"portTimeout"`
	VPNPortTimeout     int    `yaml:"VPNPortTimeout"`
}

type GatewayConfig struct {
	Ip                    string `yaml:"ip"`
	StandbyIp             string `yaml:"standbyIp"`
	Alias                 string `yaml:"alias"`
	SpaPort               int    `yaml:"spaPort"`
	CommunicationPort     int    `yaml:"communicationPort"`
	VpnPort               int    `yaml:"vpnPort"`
	IPPool                string `yaml:"ipPool"`
	SPAPortPool           string `yaml:"spaPortPool"`
	CommunicationPortPool string `yaml:"communicationPortPool"`
	VPNPortPool           string `yaml:"vpnPortPool"`
	PoolExpireTime        int    `yaml:"poolExpireTime"`
	Domain                string `yaml:"domain"`
	ThirdPartyDevice      bool   `yaml:"thirdPartyDevice"`
	StandbySPAPort        int    `yaml:"standbySPAPort"`
	StandbyCommPort       int    `yaml:"standbyCommPort"`
	StandbyVPNPort        int    `yaml:"standbyVPNPort"`
}

type KeycloakConfig struct {
	UseKeycloakAuth         bool   `yaml:"useKeycloakAuth"`
	AdminId                 string `yaml:"adminId"`
	AdminPassword           string `yaml:"adminPassword"`
	HostName                string `yaml:"hostName"`
	HostPort                int    `yaml:"hostPort"`
	HttpsPort               int    `yaml:"httpsPort"`
	HttpsTrustStorePassword string `yaml:"httpsTrustStorePassword"`

	Realm        string `yaml:"realm"`
	ClientId     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	JwtPublicKey string `yaml:"jwtPublicKey"`
}

type DatabaseConfig struct {
	DbName          string `yaml:"dbName"`
	DbAdminId       string `yaml:"dbAdminId"`
	DbAdminPassword string `yaml:"dbAdminPassword"`
}

type Config struct {
	DeviceConfig   DeviceConfig    `yaml:"deviceConfig"`
	GatewayConfig  []GatewayConfig `yaml:"gatewayConfig"`
	KeycloakConfig KeycloakConfig  `yaml:"keycloakConfig"`
	DatabaseConfig DatabaseConfig  `yaml:"databaseConfig"`
}

func getSourceIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// Function to generate OTP
func generateOTP(machineID string, sdpKeySecret string) string {
	hashAlgorithm := sha256.New()
	hashAlgorithm.Write([]byte(sdpKeySecret))
	hashAlgorithm.Write([]byte(machineID))
	hashValue := hashAlgorithm.Sum(nil)

	sdpKeySecretBase32 := base32.StdEncoding.EncodeToString(hashValue)

	t := time.Now()
	otpValue, err := totp.GenerateCodeCustom(sdpKeySecretBase32, t, totp.ValidateOpts{Period: 30, Skew: 1})
	if err != nil {
		fmt.Println("Failed to generate OTP:", err)
		return ""
	}

	return otpValue
}

func generatePacket(machineID, sdpKeySecret string, sourceIP string) []byte {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	nonce := uint16(rand.Intn(65536))
	timestamp := uint64(time.Now().Unix())
	otpValue := generateOTP(machineID, sdpKeySecret)
	hmacValue := generateHMAC(machineID, sdpKeySecret, nonce, timestamp, net.ParseIP(sourceIP), otpValue)

	packetData := append([]byte(machineID), make([]byte, MachineIDSize-len(machineID))...)
	packetData = append(packetData, byte(nonce>>8), byte(nonce))
	packetData = append(packetData, byte(timestamp>>56), byte(timestamp>>48), byte(timestamp>>40), byte(timestamp>>32), byte(timestamp>>24), byte(timestamp>>16), byte(timestamp>>8), byte(timestamp))
	packetData = append(packetData, net.ParseIP(sourceIP).To4()...)
	packetData = append(packetData, []byte(otpValue)...)
	packetData = append(packetData, make([]byte, OTPSize-len(otpValue))...)
	packetData = append(packetData, hmacValue...)

	return packetData
}

// Function to generate HMAC
func generateHMAC(machineID string, sdpKeySecret string, nonce uint16, timestamp uint64, sourceIP net.IP, otpValue string) []byte {
	// Prepare the data for HMAC calculation
	var data []byte
	data = append(data, []byte(machineID)...)
	data = append(data, make([]byte, MachineIDSize-len(machineID))...)
	nonceBytes := make([]byte, NonceSize)
	binary.BigEndian.PutUint16(nonceBytes, nonce)
	data = append(data, nonceBytes...)
	timestampBytes := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(timestampBytes, timestamp)
	data = append(data, timestampBytes...)
	data = append(data, sourceIP.To4()...)
	data = append(data, []byte(otpValue)...)
	data = append(data, make([]byte, OTPSize-len(otpValue))...)

	// Calculate  HMAC-SHA256
	hashAlgorithm := hmac.New(sha256.New, []byte(sdpKeySecret))
	hashAlgorithm.Write(data)
	hmacValue := hashAlgorithm.Sum(nil)

	return hmacValue
}

func GenerateOTP(machineID string, sdpKeySecret string) string {
	return generateOTP(machineID, sdpKeySecret)
}

func GenerateHMAC(machineID string, sdpKeySecret string, nonce uint16, timestamp uint64, sourceIP net.IP, otpValue string) []byte {
	return generateHMAC(machineID, sdpKeySecret, nonce, timestamp, sourceIP, otpValue)
}

// FillPacket creates a packet with fields filled
func FillPacket(machineID string, sdpKeySecret string) []byte {
	sourceIP := getSourceIP()
	packet := generatePacket(machineID, sdpKeySecret, sourceIP)
	return packet
}

// SendPacket sends the packet to the server
func SendSpaPacket(packet []byte, domain string, port int) error {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(domain, strconv.Itoa(port)))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("error connecting to server: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("error sending packet: %w", err)
	}

	Logger.Logf(LOGTYPE_DEBUG, LOGID_SYSTEM, "Spa packet sent successfully. Dst=%s", net.JoinHostPort(domain, strconv.Itoa(port)))

	return nil
}

// host:port 와 같은 문자열에서 port 문자열 존재시 host와 port 를 따로 리턴해준다.
// port 미 존재시 host와 0을 리턴.
func ExtractIPPortString(str string) (string, string) {
	host, port, err := net.SplitHostPort(str)
	if err != nil {
		// SplitHostPort는 IP:PORT 형태가 아니면 에러를 리턴하므로
		// 그냥 IP일 경우는 에러를 무시하고 그대로 리턴
		return str, "0"
	}
	return host, port
}

// AES 암호화 함수
func EncryptAES(plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(AES_KEY))
	if err != nil {
		return "", err
	}

	// GCM (Galois/Counter Mode) 생성
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Nonce 생성
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(crypt.Reader, nonce); err != nil {
		return "", err
	}

	// 암호화 진행
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Base64로 인코딩된 암호화 텍스트 반환
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AES 복호화 함수
func DecryptAES(encryptedText string) (string, error) {
	// Base64로 인코딩된 암호화 텍스트를 디코딩
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(AES_KEY))
	if err != nil {
		return "", err
	}

	// GCM 모드 가져오기
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 복호화 진행
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
