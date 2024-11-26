package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	url2 "net/url"
	"os"
	"strings"
	"time"

	// genians
	. "ztsdp"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Expire      int    `json:"expires_in"`
}

type User struct {
	ID         string                 `json:"id"`
	Username   string                 `json:"username"`
	Attributes map[string]interface{} `json:"attributes"`
}

type ClientScope struct {
	Id         string            `json:"id,omitempty"`
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	Attributes map[string]string `json:"attributes"`
}

type Client struct {
	Id                        string `json:"id,omitempty"`
	ClientId                  string `json:"clientId"`
	Enabled                   bool   `json:"enabled"`
	DirectAccessGrantsEnabled bool   `json:"directAccessGrantsEnabled"`
	Secret                    string `json:"secret,omitempty"`
}

type AccessTokenManager struct {
	token      string
	expireTime time.Time
}

type Validation struct {
	Length                         *LengthValidation      `json:"length,omitempty"`
	Email                          map[string]interface{} `json:"email,omitempty"`
	UpUsernameNotIdnHomograph      map[string]interface{} `json:"up-username-not-idn-homograph,omitempty"`
	UsernameProhibitedCharacters   map[string]interface{} `json:"username-prohibited-characters,omitempty"`
	PersonNameProhibitedCharacters map[string]interface{} `json:"person-name-prohibited-characters,omitempty"`
}

type LengthValidation struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
}

type Permissions struct {
	Edit []string `json:"edit,omitempty"`
	View []string `json:"view,omitempty"`
}

type Required struct {
	Roles []string `json:"roles,omitempty"`
}

type Attribute struct {
	DisplayName string                 `json:"displayName"`
	Multivalued bool                   `json:"multivalued"`
	Name        string                 `json:"name"`
	Permissions Permissions            `json:"permissions"`
	Validations Validation             `json:"validations,omitempty"`
	Required    *Required              `json:"required,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"`
}

type Group struct {
	DisplayDescription string `json:"displayDescription"`
	DisplayHeader      string `json:"displayHeader"`
	Name               string `json:"name"`
}

type UserProfile struct {
	Attributes []Attribute `json:"attributes"`
	Groups     []Group     `json:"groups"`
}

type MapperConfig struct {
	ClaimName          string `json:"claim.name"`
	ClaimValue         string `json:"claim.value,omitempty"`
	UserinfoTokenClaim string `json:"userinfo.token.claim"`
	IdTokenClaim       string `json:"id.token.claim"`
	AccessTokenClaim   string `json:"access.token.claim"`
	JsonTypeLabel      string `json:"jsonType.label"`
	UserAttribute      string `json:"user.attribute,omitempty"`
}

type Mapper struct {
	Id             string       `json:"id,omitempty"`
	Name           string       `json:"name"`
	Protocol       string       `json:"protocol"`
	ProtocolMapper string       `json:"protocolMapper"`
	Config         MapperConfig `json:"config"`
}

func NewAccessTokenManager() *AccessTokenManager {
	return &AccessTokenManager{}
}

func (a *AccessTokenManager) expireCheck() bool {
	return a.expireTime.IsZero() || time.Now().After(a.expireTime)
}

func (a *AccessTokenManager) getToken() string {
	if a.expireCheck() {
		now := time.Now()
		url := fmt.Sprintf("https://%s:%d/realms/master/protocol/openid-connect/token", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort)

		data := url2.Values{}
		data.Set("grant_type", "password")
		data.Set("client_id", "admin-cli")
		data.Set("username", config.KeycloakConfig.AdminId)
		data.Set("password", config.KeycloakConfig.AdminPassword)

		tokenRes := TokenResponse{}
		headers := make(map[string]string)
		err := requestURLEncoded(url, "POST", data, headers, true, &tokenRes)
		if err != nil {
			log.Println(err.Error())
		}
		a.token = tokenRes.AccessToken
		a.expireTime = now.Add(time.Duration(tokenRes.Expire) * time.Second)

		return a.token
	}
	return a.token
}

var (
	atm                = NewAccessTokenManager()
	CLIENT_NAME        = "ztna-sdp"
	GATEWAY_SCOPE_NAME = "gateways"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func httpsRequest(req *http.Request) ([]byte, error) {
	// Client 인증서 로드
	cert, err := tls.LoadX509KeyPair("/ztsdp/keycloak/cert/client.crt", "/ztsdp/keycloak/cert/client.key")
	if err != nil {
		log.Print(err.Error())
	}

	// Load server CA certificate
	caCert, err := os.ReadFile("/ztsdp/cert/ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create tls.Config with root CA
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Create a transport with the TLS config
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr, Timeout: time.Second * 10}
	res, err := client.Do(req)
	if err != nil {
		log.Print(err.Error())
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode >= http.StatusBadRequest {
		Logger.LogWithFields(LOGTYPE_DEBUG, LOGID_KEYCLOAK, "Http request error.", Fields{"Msg": string(resBody)})
	}

	return resBody, nil
}

func requestURLEncoded(url string, method string, values url2.Values, headers map[string]string, needUnmarshal bool, obj interface{}) error {
	body := strings.NewReader(values.Encode())
	req, _ := http.NewRequest(method, url, body)
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	result, err := httpsRequest(req)
	if err != nil {
		log.Println(err.Error())
	}

	if needUnmarshal {
		err = json.Unmarshal(result, &obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func requestJson(url string, method string, jsonData []byte, headers map[string]string, needUnmarshal bool, obj interface{}) error {
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	req.Header.Add("Content-Type", "application/json")

	result, err := httpsRequest(req)
	if err != nil {
		log.Println(err.Error())
	}

	if needUnmarshal {
		err = json.Unmarshal(result, &obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func getUsersWithMID(mid string) ([]User, error) {
	accessToken := atm.getToken()
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/users?q=MID:%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, mid)

	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	data := url2.Values{}

	var userRes []User
	err := requestURLEncoded(url, "GET", data, headers, true, &userRes)
	if err != nil {
		log.Println(err.Error())
	}

	return userRes, nil
}

func getUserByID(id string) (User, error) {
	accessToken := atm.getToken()
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/users/%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, id)

	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	data := url2.Values{}

	var userRes User
	err := requestURLEncoded(url, "GET", data, headers, true, &userRes)
	if err != nil {
		log.Println(err.Error())
	}
	return userRes, err
}

func updateUserAttribute(id string, attrs map[string]interface{}) error {
	accessToken := atm.getToken()

	user, err := getUserByID(id)
	if err != nil {
		log.Println(err.Error())
	}

	for k, v := range attrs {
		user.Attributes[k] = v

		url := fmt.Sprintf("https://%s:%d/admin/realms/%s/users/%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, id)

		headers := map[string]string{"Authorization": "Bearer " + accessToken}

		userData, err := json.Marshal(user)
		if err != nil {
			log.Println(err.Error())
		}

		err = requestJson(url, "PUT", userData, headers, false, nil)
		if err != nil {
			return err
		}

	}

	return nil
}

func updateUserSecret(userID string, machineID string, secretKey string, attrName string) error {
	attr := make(map[string]interface{})
	attr["MID"] = machineID
	attr[attrName] = secretKey

	err := updateUserAttribute(userID, attr)
	if err != nil {
		return err
	}
	return nil
}

func createRealm() {
	accessToken := atm.getToken()

	url := fmt.Sprintf("https://%s:%d/admin/realms/%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := map[string]string{"Authorization": "Bearer " + accessToken}
	type Realm struct {
		Realm       string `json:"realm"`
		Enabled     bool   `json:"enabled"`
		DisplayName string `json:"displayName"`
	}
	realm := Realm{}
	err := requestJson(url, "GET", nil, headers, true, &realm)
	if err != nil {
		log.Println(err.Error())
	}

	if realm.Realm == "" {
		url := fmt.Sprintf("https://%s:%d/admin/realms", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort)
		headers := map[string]string{"Authorization": "Bearer " + accessToken}

		realm := Realm{}
		realm.Realm = config.KeycloakConfig.Realm
		realm.Enabled = true
		realm.DisplayName = config.KeycloakConfig.Realm

		realmData, err := json.Marshal(realm)
		if err != nil {
			log.Println(err.Error())
		}
		err = requestJson(url, "POST", realmData, headers, false, nil)
		if err != nil {
			Logger.LogWithFields(LOGTYPE_ERROR, LOGID_KEYCLOAK, "Realm creation failed.", Fields{"realm": config.KeycloakConfig.Realm, "error": err.Error()})
		} else {
			Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Create a realm.", Fields{"realm": config.KeycloakConfig.Realm})
		}
	}
}

func getUserProfileConfig() (map[string]interface{}, error) {
	accessToken := atm.getToken()

	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/users/profile", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	var profile map[string]interface{}
	err := requestJson(url, "GET", nil, headers, true, &profile)
	if err != nil {
		Logger.LogWithFields(LOGTYPE_ERROR, LOGID_KEYCLOAK, "User profile get failed.", Fields{"realm": config.KeycloakConfig.Realm, "error": err.Error()})
		return profile, err
	}
	return profile, nil
}

func createUserProfile(attrName string) {
	accessToken := atm.getToken()

	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/users/profile", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	findAttr := false
	profiles, err := getUserProfileConfig()
	if err != nil {
	} else {
		if attribute, ok := profiles["attributes"].([]interface{}); ok {
			for _, attr := range attribute {
				if attribute, ok := attr.(map[string]interface{}); ok {
					if name, ok := attribute["name"].(string); ok {
						if name == attrName {
							findAttr = true
							break
						}
					}
				}
			}
		}
	}

	if !findAttr {
		newAttribute := map[string]interface{}{
			"name":        attrName,
			"displayName": "",
			"permissions": map[string]interface{}{
				"view": []string{"admin", "user"},
				"edit": []string{"admin"},
			},
			"multivalued": false,
		}

		if attribute, ok := profiles["attributes"].([]interface{}); ok {
			profiles["attributes"] = append(attribute, newAttribute)
		}

		profileData, err := json.Marshal(profiles)
		if err != nil {
			log.Println(err.Error())
		}

		err = requestJson(url, "PUT", profileData, headers, false, nil)
		if err != nil {
			log.Println(err.Error())
		}
	}
}

func createClient() {
	accessToken := atm.getToken()

	clientId := getClientID(accessToken, CLIENT_NAME)

	if clientId == "" {
		url := fmt.Sprintf("https://%s:%d/admin/realms/%s/clients", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
		headers := map[string]string{"Authorization": "Bearer " + accessToken}
		client := Client{}
		client.ClientId = CLIENT_NAME
		client.Enabled = true
		client.DirectAccessGrantsEnabled = true

		if config.KeycloakConfig.ClientSecret != "" {
			client.Secret = config.KeycloakConfig.ClientSecret
		}

		clientData, err := json.Marshal(client)
		if err != nil {
			log.Println(err.Error())
		}

		err = requestJson(url, "POST", clientData, headers, false, nil)
		if err != nil {
			Logger.LogWithFields(LOGTYPE_ERROR, LOGID_KEYCLOAK, "Client creation failed.", Fields{"client": CLIENT_NAME, "error": err.Error()})
		} else {
			Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Create a client.", Fields{"client": CLIENT_NAME})
		}
	}
}

func createClientScope() {
	accessToken := atm.getToken()

	scopeId := getClientScopeID(accessToken, GATEWAY_SCOPE_NAME)

	if scopeId == "" {
		url := fmt.Sprintf("https://%s:%d/admin/realms/%s/client-scopes", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
		headers := map[string]string{"Authorization": "Bearer " + accessToken}

		scope := ClientScope{}
		scope.Name = GATEWAY_SCOPE_NAME
		scope.Protocol = "openid-connect"

		scopeData, err := json.Marshal(scope)
		if err != nil {
			log.Println(err.Error())
		}

		err = requestJson(url, "POST", scopeData, headers, false, nil)
		if err != nil {
			log.Println(err.Error())
		}
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Create client scope.", Fields{"scopeName": scope.Name})

		// add client scope to client
		clientId := getClientID(accessToken, CLIENT_NAME)
		scopeId = getClientScopeID(accessToken, GATEWAY_SCOPE_NAME)
		url = fmt.Sprintf("https://%s:%d/admin/realms/%s/clients/%s/default-client-scopes/%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, clientId, scopeId)
		err = requestJson(url, "PUT", nil, headers, false, nil)
		if err != nil {
			log.Println(err.Error())
		}
		Logger.Log(LOGTYPE_INFO, LOGID_KEYCLOAK, "Client scope was added to Client.")
	}
}

func getClientID(token string, name string) string {
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/clients", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := map[string]string{"Authorization": "Bearer " + token}
	type Realm struct {
		Realm string `json:"realm"`
	}
	realm := Realm{}
	realm.Realm = config.KeycloakConfig.Realm
	realmData, err := json.Marshal(realm)
	if err != nil {
		log.Println(err.Error())
	}

	var clients []Client
	err = requestJson(url, "GET", realmData, headers, true, &clients)
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	id := ""
	for _, client := range clients {
		if client.ClientId == name {
			id = client.Id
			break
		}
	}
	return id
}

func getClientSecret(token string, clientID string) string {
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/clients/%s/client-secret", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, clientID)
	headers := map[string]string{"Authorization": "Bearer " + token}
	type Realm struct {
		Realm string `json:"realm"`
	}

	type ClientSecretResponse struct {
		Value string `json:"value"`
	}

	res := ClientSecretResponse{}
	err := requestJson(url, "GET", nil, headers, true, &res)
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	return res.Value
}

func getClientScopeID(token string, name string) string {
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/client-scopes", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := map[string]string{"Authorization": "Bearer " + token}
	data := url2.Values{}

	var scopes []ClientScope
	err := requestURLEncoded(url, "GET", data, headers, true, &scopes)
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	id := ""
	for _, scope := range scopes {
		if scope.Name == name {
			id = scope.Id
			break
		}
	}
	return id
}

func createMapper(scopeId string, mapper *Mapper, mapperType string, protocolMapper string) {
	accessToken := atm.getToken()

	mapper.Protocol = "openid-connect"
	mapper.ProtocolMapper = protocolMapper

	mapper.Config.UserinfoTokenClaim = "true"
	mapper.Config.IdTokenClaim = "true"
	mapper.Config.AccessTokenClaim = "true"
	mapper.Config.JsonTypeLabel = mapperType

	mapperData, err := json.Marshal(mapper)
	if err != nil {
		log.Println(err.Error())
	}

	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/client-scopes/%s/protocol-mappers/models", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, scopeId)

	headers := map[string]string{"Authorization": "Bearer " + accessToken}
	err = requestJson(url, "POST", mapperData, headers, false, nil)
	if err != nil {
		log.Println(err.Error())
	}
	Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Create Mapper.", Fields{"Name": mapper.Name})
}

func updateGatewayInfo() {
	accessToken := atm.getToken()

	// client scope ID를 얻어온다.
	var scopeId string

	scopeId = getClientScopeID(accessToken, GATEWAY_SCOPE_NAME)

	// 해당 scope 가 가진 mapper 를 얻어온다.
	url := fmt.Sprintf("https://%s:%d/admin/realms/%s/client-scopes/%s/protocol-mappers/models", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, scopeId)
	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	var mappers []Mapper

	err := requestJson(url, "GET", nil, headers, true, &mappers)
	if err != nil {
		log.Println(err.Error())
	}

	// 모든 mapper 삭제
	for _, mapper := range mappers {
		url := fmt.Sprintf("https://%s:%d/admin/realms/%s/client-scopes/%s/protocol-mappers/models/%s", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm, scopeId, mapper.Id)
		headers := map[string]string{"Authorization": "Bearer " + accessToken}

		err := requestJson(url, "DELETE", nil, headers, false, nil)
		if err != nil {
			log.Println(err.Error())
		}
	}

	for idx, gateway := range config.GatewayConfig {
		//gateway alias
		mc := Mapper{}
		mc.Name = fmt.Sprintf("gw%d-alias", idx+1)
		mc.Config.ClaimValue = gateway.Alias
		mc.Config.ClaimName = fmt.Sprintf("gw%d-alias", idx+1)

		createMapper(scopeId, &mc, "string", "oidc-hardcoded-claim-mapper")

		kinds := []string{"agw", "sgw"}
		for _, kind := range kinds {
			var gw string

			if kind == "agw" {
				gw = fmt.Sprintf("%s:%d", gateway.Ip, gateway.VpnPort)
			} else {
				gw = fmt.Sprintf("%s:%d", gateway.Ip, gateway.SpaPort)
			}

			mc.Name = fmt.Sprintf("gw%d-%s", idx+1, kind)
			mc.Config.ClaimValue = gw
			mc.Config.ClaimName = fmt.Sprintf("gw%d-%s", idx+1, kind)

			createMapper(scopeId, &mc, "string", "oidc-hardcoded-claim-mapper")
		}

		// sky attribute
		mc = Mapper{}
		mc.Config.ClaimName = fmt.Sprintf("gw%d-sky", idx+1)
		mc.Config.UserAttribute = fmt.Sprintf("gw%d-sky", idx+1)
		mc.Name = fmt.Sprintf("gw%d-secret", idx+1)

		createMapper(scopeId, &mc, "string", "oidc-usermodel-attribute-mapper")

		// third-party device
		mc = Mapper{}
		mc.Name = fmt.Sprintf("gw%d-thirdPartyDevice", idx+1)
		if gateway.ThirdPartyDevice {
			mc.Config.ClaimValue = "true"
		} else {
			mc.Config.ClaimValue = "false"
		}
		mc.Config.ClaimName = fmt.Sprintf("gw%d-thirdPartyDevice", idx+1)

		createMapper(scopeId, &mc, "boolean", "oidc-hardcoded-claim-mapper")
	}
}

func loginKeycloak(id string, password string) string {
	accessToken := atm.getToken()
	clientId := getClientID(accessToken, CLIENT_NAME)

	clientSecret := getClientSecret(accessToken, clientId)

	url := fmt.Sprintf("https://%s:%d/realms/%s/protocol/openid-connect/token", config.KeycloakConfig.HostName, config.KeycloakConfig.HostPort, config.KeycloakConfig.Realm)
	headers := make(map[string]string)
	data := url2.Values{}

	data.Set("client_id", CLIENT_NAME)
	data.Set("client_secret", clientSecret)
	data.Set("username", id)
	data.Set("password", password)
	data.Set("grant_type", "password")

	var result map[string]interface{}
	err := requestURLEncoded(url, "POST", data, headers, true, &result)
	if err != nil {
		log.Println(err.Error())
	}

	token, ok := result["access_token"]
	if !ok {
		errmeMessage, ok := result["error"]
		if ok {
			errmeMessage2, ok := result["error_description"]
			if ok {
				Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to keycloak autentication.", Fields{"ERROR": errmeMessage, "DESC": errmeMessage2})
			} else {
				Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to keycloak autentication.", Fields{"ERROR": errmeMessage})
			}
		} else {
			Logger.Log(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to keycloak autentication.")
		}
		return ""
	}
	if token == nil || token.(string) == "" {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to keycloak autentication.", Fields{"ERROR": "Access token is empty."})
	}

	parts := strings.Split(token.(string), ".")
	if len(parts) != 3 {
		Logger.Log(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to parge access token. Invalid format.")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		Logger.LogWithFields(LOGTYPE_INFO, LOGID_KEYCLOAK, "Failed to decoding payload.", Fields{"ERROR": err.Error()})
	}
	// 응답 토큰 데이터 (JSON)
	Logger.Log(LOGTYPE_INFO, LOGID_KEYCLOAK, "Result token:"+string(payload))

	// JSON unmarshal
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)

	return ""
}
