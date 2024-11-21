package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	// "software.sslmate.com/src/go-pkcs12" // pkcs12 패키지 사용
)

type User struct {
	UserId string `json:"user_id"`
	Pswd   string `json:"pswd"`
}

func main() {

	// ca 인증서 넣기
	caCert, err := ioutil.ReadFile("/home/jasper/cert/ca.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	//client 인증서 넣기
	clientCert, err := tls.LoadX509KeyPair("/home/jasper/cert/client.crt", "/home/jasper/cert/client.key")
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}

	// CA 인증서로 인증서 풀 생성
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 5. TLS 설정 구성
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert}, // 클라이언트 인증서 설정
		RootCAs:      caCertPool,                    // 서버의 CA 인증서 설정
		//	InsecureSkipVerify: true,
		//ClientAuth: tls.RequireAndVerifyClientCert, // 클라이언트 인증 필수 및 검증
	}

	//6. HTTPS 클라이언트 생성
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// 빈 POST 요청 데이터
	user := User{
		UserId: "test110",
		Pswd:   "14e8639d168c8ae7ee7a8abc32e8ed7b0d92488664bb5328c30137a9ccf4dff9",
		//Otp_Number: "178198",
	}
	jsonData, err := json.Marshal(user)
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}

	fmt.Printf("UserId: %s, Pswd: %s\n", user.UserId, user.Pswd)

	// POST 요청
	//url := "https://cds.nsr.kr:1091/getPortList"
	url := "https://110.15.243.71:1088/IdPwCheck"
	//url := "https://110.15.243.71:1089/OtpCheck"
	//url := "https://110.15.243.71:1090/SessionDestroy"
	resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Failed to make POST request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 응답 확인
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response body: %v\n", err)
		return
	}

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", body)
}
