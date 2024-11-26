package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"

	// genians
	. "ztsdp"
)

var (
	EVENT_AUTH     = 1
	EVENT_IPCHANGE = 2

	EVENTRESULT_ERROR   = -1
	EVENTRESULT_SUCCESS = 0
	EVENTRESULT_HAVEVPN = 1
)

// controller -> gateway 이벤트
type EventData struct {
	EventId           int                       `json:"eventId"`
	AuthData          AuthJsonData              `json:"authData"`
	IPData            IPJsonData                `json:"IPData"`
	SPAData           SPAPortJsonData           `json:"SPAData"`
	CommunicationData CommunicationPortJsonData `json:"communicationData"`
	VPNData           VpnPortJsonData           `json:"VPNData"`
}

type EventResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type AuthJsonData struct {
	SourceIP  string `json:"sourceIP"`
	MachineID string `json:"machineID"`
	Secret    string `json:"secret"`
}

type IPJsonData struct {
	OldIP string `json:"oldIP"`
	NewIP string `json:"newIP"`
}

type SPAPortJsonData struct {
	OldPort string `json:"oldPort"`
	NewPort string `json:"newPort"`
}

type CommunicationPortJsonData struct {
	OldPort string `json:"oldPort"`
	NewPort string `json:"newPort"`
}

type VpnPortJsonData struct {
	OldPort string `json:"oldPort"`
	NewPort string `json:"newPort"`
}

func parseRSAPublicKeyFromPEM(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

type CustomClaims struct {
	jwt.StandardClaims
}

func (c CustomClaims) Valid() error {
	// Skip the expiry time check
	return nil
}

func startWSS(servicePort string) {

	// Define websocket handler function
	handleWebSocket := func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		// Upgrade HTTP connection to websocket connection
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		if isGateway() {
			for {
				// Read message from client
				_, p, err := conn.ReadMessage()
				if err != nil {
					return
				}

				// Process received JSON
				var data EventData
				if err := json.Unmarshal(p, &data); err != nil {
					Logger.LogWithFields(LOGTYPE_ERROR, LOGID_EVENT, "Unmarshaling error.", Fields{"Error": err.Error()})
					return
				}
				Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Received data from controller.",
					Fields{"EventID": strconv.Itoa(data.EventId)})

				switch data.EventId {
				case EVENT_AUTH:
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Received auth event.",
						Fields{"SourceIP": data.AuthData.SourceIP, "MachineID": data.AuthData.MachineID, "SecretKey": data.AuthData.Secret})
					authData := AuthData{
						SourceIP: data.AuthData.SourceIP,
						SdpKey:   data.AuthData.Secret,
					}

					// save authorized machineid & dynamic secret
					authManager.storeData(data.AuthData.MachineID, authData)
				case EVENT_IPCHANGE:
					Logger.LogWithFields(LOGTYPE_INFO, LOGID_EVENT, "Received ip change event.",
						Fields{"IP": data.IPData.NewIP})

					haveSession, err := checkVPNSession()
					if err == nil {
						if haveSession {
							res := EventResponse{
								Code:    EVENTRESULT_HAVEVPN,
								Message: "IP change failed because session exists.",
							}
							conn.WriteJSON(res)
						} else {
							res := EventResponse{
								Code:    EVENTRESULT_SUCCESS,
								Message: "IP change success.",
							}
							conn.WriteJSON(res)

							changeIP(data.IPData.OldIP, data.IPData.NewIP)

							IptableManager.deleteRoutingRule(sdpPreRoutingChain, "-s", config.DeviceConfig.ControllerIP, "-p", protoUDP, "--dport", data.SPAData.OldPort)
							changePort("SPA", data.SPAData.OldPort, data.SPAData.NewPort)
							IptableManager.createRoutingRule(sdpPreRoutingChain, "-s", config.DeviceConfig.ControllerIP, "-p", protoUDP, "--dport", data.SPAData.NewPort)

							changePort("COMMUNICATION", data.CommunicationData.OldPort, data.CommunicationData.NewPort)

							oldDst := fmt.Sprintf("%s:1194", data.IPData.OldIP)
							IptableManager.deleteRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", strconv.Itoa(config.DeviceConfig.VpnPort), "-j", "DNAT", "--to-destination", oldDst)
							IptableManager.deleteRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", data.VPNData.OldPort, "-j", "MARK", "--set-mark", "111")
							changePort("VPN", data.VPNData.OldPort, data.VPNData.NewPort)
							newDst := fmt.Sprintf("%s:1194", data.IPData.NewIP)
							IptableManager.createRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", strconv.Itoa(config.DeviceConfig.VpnPort), "-j", "DNAT", "--to-destination", newDst)
							IptableManager.createRoutingRule(sdpPreRoutingChain, "-p", "tcp", "--dport", data.VPNData.NewPort, "-j", "MARK", "--set-mark", "111")

							Logger.Log(LOGTYPE_INFO, LOGID_EVENT, "Daemon restart because of IP/Port change.")
							os.Exit(-1)
						}
					} else {
						res := EventResponse{
							Code:    EVENTRESULT_ERROR,
							Message: "VPN session check failed. Error" + err.Error(),
						}
						conn.WriteJSON(res)
					}

				}

			}
		}
	}

	// Register websocket handler function for "/ws" path
	http.HandleFunc("/ws", handleWebSocket)

	Logger.LogWithFields(LOGTYPE_INFO, LOGID_SYSTEM, "Data channel has been opened.", Fields{"Port": servicePort})

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("/ztsdp/sdp/cert/server.crt", "/ztsdp/sdp/cert/server.key")
	if err != nil {
		log.Fatal(err)
	}

	// Load client CA certificate
	caCert, err := ioutil.ReadFile("/ztsdp/cert/ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create tls.Config with client CA
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // 클라이언트 인증서 인증
	}

	servicePort = ":" + servicePort
	server := &http.Server{
		Addr:      servicePort,
		Handler:   nil,
		TLSConfig: config,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal("Web socket server failed to start:", err)
	}
}

func sendSdpData(eventType int, data interface{}, domain string, gatewayServicePort int) error {
	serverURL := fmt.Sprintf("wss://%s:%d/ws", domain, gatewayServicePort)

	u, err := url.Parse(serverURL)
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}

	// Resolve the IP address of the host
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		log.Fatalf("Failed to resolve IP address: %v", err)
	}

	// Print the IP addresses
	for _, ip := range ips {
		log.Printf("Resolved IP: %s", ip.String())
	}

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair("/ztsdp/sdp/cert/client.crt", "/ztsdp/sdp/cert/client.key")
	if err != nil {
		log.Fatal(err)
	}

	// Load server CA certificate
	caCert, err := os.ReadFile("/ztsdp/cert/ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create tls.Config with root CA
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Create dialer with tls.Config
	dialer := websocket.Dialer{
		TLSClientConfig:  config,
		HandshakeTimeout: 10 * time.Second,
	}

	// Dial websocket server
	conn, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		Logger.LogWithFields(LOGTYPE_ERROR, LOGID_SYSTEM, "Gateway connection failed.", Fields{"Error": err.Error()})
		return err
	}
	defer conn.Close()

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
	}

	// Send the JSON data to the WebSocket server
	err = conn.WriteMessage(websocket.TextMessage, jsonData)
	if err != nil {
		return err
	}
	if eventType == EVENT_AUTH {
		return nil
	}

	for {
		// Read message from client
		_, p, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var res EventResponse
		if err := json.Unmarshal(p, &res); err != nil {
			Logger.LogWithFields(LOGTYPE_ERROR, LOGID_EVENT, "Unmarshaling error.", Fields{"Error": err.Error()})
			return err
		} else {
			if res.Code != EVENTRESULT_SUCCESS {
				return errors.New(res.Message)
			}
			return nil
		}
	}

	return nil
}

func sendAuthEvent(domain string, gatewayServicePort int, sourceIP string, machineID string, secretKey string) {
	// Create a AuthJsonData struct and convert it to JSON
	data := AuthJsonData{
		SourceIP:  sourceIP,
		MachineID: machineID,
		Secret:    secretKey,
	}
	event := EventData{
		EventId:  EVENT_AUTH,
		AuthData: data,
	}
	sendSdpData(EVENT_AUTH, event, domain, gatewayServicePort)
}

func sendIPPortChangeEvent(domain string, gatewayServicePort int, ipData IPJsonData, spaPortData SPAPortJsonData, commPortData CommunicationPortJsonData, vpnPortData VpnPortJsonData) error {
	fmt.Printf("send Ip change event")
	// Create a AuthJsonData struct and convert it to JSON

	event := EventData{
		EventId:           EVENT_IPCHANGE,
		IPData:            ipData,
		SPAData:           spaPortData,
		CommunicationData: commPortData,
		VPNData:           vpnPortData,
	}
	return sendSdpData(EVENT_IPCHANGE, event, domain, gatewayServicePort)
}
