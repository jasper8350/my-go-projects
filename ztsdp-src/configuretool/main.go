package main

import (
	"crypto/rand"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"gopkg.in/yaml.v3"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/uuid"
	. "ztsdp"
)

const (
	ZTSDPD_CONF_PATH  = "/etc/ztsdpd.yaml"
	KCADMIN_CONF_PATH = "/etc/kcadmin.conf"

	KEYCLOAK_CA_CERT_DIR = "/ztsdp/cert"
	KEYCLOAK_CERT_DIR    = "/ztsdp/keycloak/cert"
	KEYCLOAK_USER_DIR    = KEYCLOAK_CERT_DIR + "/user"
)

var (
	oldConf Config
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func init() {
	if _, err := os.Stat(ZTSDPD_CONF_PATH); err == nil {

		file, _ := os.ReadFile(ZTSDPD_CONF_PATH)
		err = yaml.Unmarshal(file, &oldConf)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		b[i] = letterBytes[num.Int64()]
	}
	return string(b)
}

func main() {
	app := tview.NewApplication()
	form := tview.NewForm()

	// device config
	menu := map[int]string{0: "controller", 1: "gateway"}
	role := tview.NewDropDown().SetLabel("role?").SetOptions([]string{menu[0], menu[1]}, nil)
	if oldConf.DeviceConfig.Role != "" {
		for k, v := range menu {
			if v == oldConf.DeviceConfig.Role {
				role.SetCurrentOption(k)
			}
		}
	}
	primaryIP := tview.NewInputField().SetLabel("primary ip?").SetFieldWidth(30)
	if len(oldConf.DeviceConfig.PrimaryIP) > 1 {
		primaryIP.SetText(oldConf.DeviceConfig.PrimaryIP)
	}

	spaPort := tview.NewInputField().SetLabel("SPA port?").SetFieldWidth(10)
	if oldConf.DeviceConfig.SpaPort != 0 {
		spaPort.SetText(strconv.Itoa(oldConf.DeviceConfig.SpaPort))
	} else {
		spaPort.SetText("50001")
	}
	communicationPort := tview.NewInputField().SetLabel("communication port?").SetFieldWidth(10)
	if oldConf.DeviceConfig.CommunicationPort != 0 {
		communicationPort.SetText(strconv.Itoa(oldConf.DeviceConfig.CommunicationPort))
	} else {
		communicationPort.SetText("50004")
	}

	controllerIP := tview.NewInputField().SetLabel("controller ip?").SetFieldWidth(30)
	if len(oldConf.DeviceConfig.ControllerIP) > 1 {
		controllerIP.SetText(oldConf.DeviceConfig.ControllerIP)
	}

	spaGlobalSecret := tview.NewInputField().SetLabel("spa global secret?").SetFieldWidth(50)
	if len(oldConf.DeviceConfig.SpaGlobalSecret) > 1 {
		spaGlobalSecret.SetText(oldConf.DeviceConfig.SpaGlobalSecret)
	}

	controllerUUID := tview.NewInputField().SetLabel("controller uuid?").SetFieldWidth(50)
	if len(oldConf.DeviceConfig.ControllerUUID) > 1 {
		controllerUUID.SetText(oldConf.DeviceConfig.ControllerUUID)
	}

	vpnPort := tview.NewInputField().SetLabel("vpn port?").SetFieldWidth(10)
	if oldConf.DeviceConfig.VpnPort != 0 {
		vpnPort.SetText(strconv.Itoa(oldConf.DeviceConfig.VpnPort))
	} else {
		vpnPort.SetText("1194")
	}
	policyServerIp := tview.NewInputField().SetLabel("policy server ip?").SetFieldWidth(30)
	if oldConf.DeviceConfig.PolicyServerIP != "" {
		policyServerIp.SetText(oldConf.DeviceConfig.PolicyServerIP)
	}
	policyServerAPIKey := tview.NewInputField().SetLabel("policy server API key?").SetFieldWidth(30)
	if oldConf.DeviceConfig.PolicyServerAPIKey != "" {
		policyServerAPIKey.SetText(oldConf.DeviceConfig.PolicyServerAPIKey)
	}
	sshAllowedIp := tview.NewInputField().SetLabel("ssh allowed ip?").SetFieldWidth(30)
	if oldConf.DeviceConfig.SshAllowedIP != "" {
		sshAllowedIp.SetText(oldConf.DeviceConfig.SshAllowedIP)
	}

	//gateway config
	gw1Alias := tview.NewInputField().SetLabel("gateway 1 alias?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 {
		gw1Alias.SetText(oldConf.GatewayConfig[0].Alias)
	}
	gw1Domain := tview.NewInputField().SetLabel("gateway 1 domain(required)?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 {
		gw1Domain.SetText(oldConf.GatewayConfig[0].Domain)
	}
	gw1Ip := tview.NewInputField().SetLabel("gateway 1 ip?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 {
		gw1Ip.SetText(oldConf.GatewayConfig[0].Ip)
	}
	gw1StandByIp := tview.NewInputField().SetLabel("gateway 1 standby ip?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 {
		gw1StandByIp.SetText(oldConf.GatewayConfig[0].StandbyIp)
	}
	gw1StandBySpaPort := tview.NewInputField().SetLabel("gateway 1 standby spa port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].StandbyVPNPort != 0 {
		gw1StandBySpaPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].StandbyVPNPort))
	}
	gw1StandByCommunicationPort := tview.NewInputField().SetLabel("gateway 1 standby communication port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].StandbyCommPort != 0 {
		gw1StandByCommunicationPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].StandbyCommPort))
	}
	gw1StandByVpnPort := tview.NewInputField().SetLabel("gateway 1 standby vpn port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].StandbyVPNPort != 0 {
		gw1StandByVpnPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].StandbyVPNPort))
	}
	gw1IPPool := tview.NewInputField().SetLabel("gateway 1 ip pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && len(oldConf.GatewayConfig[0].IPPool) > 0 {
		gw1IPPool.SetText(oldConf.GatewayConfig[0].IPPool)
	}
	gw1SPAPool := tview.NewInputField().SetLabel("gateway 1 SPA port pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && len(oldConf.GatewayConfig[0].SPAPortPool) > 0 {
		gw1SPAPool.SetText(oldConf.GatewayConfig[0].SPAPortPool)
	}
	gw1CommunicationPortPool := tview.NewInputField().SetLabel("gateway 1 communication port pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 0 && len(oldConf.GatewayConfig[0].CommunicationPortPool) > 0 {
		gw1CommunicationPortPool.SetText(oldConf.GatewayConfig[0].CommunicationPortPool)
	}
	gw1IPExpireTime := tview.NewInputField().SetLabel("gateway 1 ip expire time?").SetFieldWidth(15).SetPlaceholder("unit: minutes")
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].PoolExpireTime > 0 {
		gw1IPPool.SetText(strconv.Itoa(oldConf.GatewayConfig[0].PoolExpireTime))
	}
	gw1ThirdPartyDev := tview.NewCheckbox().SetLabel("gateway 1 third-party device?")
	if len(oldConf.GatewayConfig) > 0 {
		gw1ThirdPartyDev.SetChecked(oldConf.GatewayConfig[0].ThirdPartyDevice)
	}

	gw2Alias := tview.NewInputField().SetLabel("gateway 2 alias?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 {
		gw2Alias.SetText(oldConf.GatewayConfig[1].Alias)
	}
	gw2Domain := tview.NewInputField().SetLabel("gateway 2 domain(required)?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 {
		gw2Domain.SetText(oldConf.GatewayConfig[1].Domain)
	}
	gw2Ip := tview.NewInputField().SetLabel("gateway 2 ip?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 {
		gw2Ip.SetText(oldConf.GatewayConfig[1].Ip)
	}
	gw2StandByIp := tview.NewInputField().SetLabel("gateway 2 standby ip?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 {
		gw2StandByIp.SetText(oldConf.GatewayConfig[1].StandbyIp)
	}
	gw2StandBySpaPort := tview.NewInputField().SetLabel("gateway 2 standby spa port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && oldConf.GatewayConfig[1].StandbySPAPort != 0 {
		gw2StandBySpaPort.SetText(strconv.Itoa(oldConf.GatewayConfig[1].StandbyVPNPort))
	}
	gw2StandByCommunicationPort := tview.NewInputField().SetLabel("gateway 2 standby communication port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && oldConf.GatewayConfig[1].StandbyCommPort != 0 {
		gw2StandByCommunicationPort.SetText(strconv.Itoa(oldConf.GatewayConfig[1].StandbyCommPort))
	}
	gw2StandByVpnPort := tview.NewInputField().SetLabel("gateway 2 standby vpn port?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && oldConf.GatewayConfig[1].StandbyVPNPort != 0 {
		gw2StandByVpnPort.SetText(strconv.Itoa(oldConf.GatewayConfig[1].StandbyVPNPort))
	}
	gw2IPPool := tview.NewInputField().SetLabel("gateway 2 ip pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && len(oldConf.GatewayConfig[1].IPPool) > 0 {
		gw2IPPool.SetText(oldConf.GatewayConfig[1].IPPool)
	}
	gw2SPAPool := tview.NewInputField().SetLabel("gateway 2 SPA port pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && len(oldConf.GatewayConfig[1].SPAPortPool) > 0 {
		gw2SPAPool.SetText(oldConf.GatewayConfig[1].SPAPortPool)
	}
	gw2CommunicationPortPool := tview.NewInputField().SetLabel("gateway 2 communication port pool?").SetFieldWidth(30)
	if len(oldConf.GatewayConfig) > 1 && len(oldConf.GatewayConfig[1].CommunicationPortPool) > 0 {
		gw2CommunicationPortPool.SetText(oldConf.GatewayConfig[1].CommunicationPortPool)
	}
	gw2IPExpireTime := tview.NewInputField().SetLabel("gateway 2 ip expire time?").SetFieldWidth(15).SetPlaceholder("unit: minutes")
	if len(oldConf.GatewayConfig) > 1 && oldConf.GatewayConfig[1].PoolExpireTime > 0 {
		gw2IPExpireTime.SetText(strconv.Itoa(oldConf.GatewayConfig[1].PoolExpireTime))
	}
	gw2ThirdPartyDev := tview.NewCheckbox().SetLabel("gateway 2 third-party device?")
	if len(oldConf.GatewayConfig) > 1 {
		gw2ThirdPartyDev.SetChecked(oldConf.GatewayConfig[1].ThirdPartyDevice)
	}

	gwSpaPort := tview.NewInputField().SetLabel("gateway spa port?").SetFieldWidth(10)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].SpaPort != 0 {
		gwSpaPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].SpaPort))
	} else {
		gwSpaPort.SetText("50001")
	}

	gwCommunicationPort := tview.NewInputField().SetLabel("gateway communication port?").SetFieldWidth(10)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].CommunicationPort != 0 {
		gwCommunicationPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].CommunicationPort))
	} else {
		gwCommunicationPort.SetText("50004")
	}

	gwVPNPort := tview.NewInputField().SetLabel("gateway vpn port?").SetFieldWidth(10)
	if len(oldConf.GatewayConfig) > 0 && oldConf.GatewayConfig[0].VpnPort != 0 {
		gwVPNPort.SetText(strconv.Itoa(oldConf.GatewayConfig[0].VpnPort))
	} else {
		gwVPNPort.SetText("1194")
	}

	//keycloak
	keycloakUse := tview.NewCheckbox().SetLabel("use keycloak auth?")
	keycloakUse.SetChecked(true)
	keycloakAdmin := tview.NewInputField().SetLabel("keycloak admin id?").SetFieldWidth(30)
	keycloakAdmin.SetText(oldConf.KeycloakConfig.AdminId)
	keycloakAdminPassword := tview.NewInputField().SetLabel("keycloak admin password?").SetFieldWidth(30).SetMaskCharacter('*')
	if len(oldConf.KeycloakConfig.AdminPassword) > 0 {
		keycloakAdminPassword.SetText(oldConf.KeycloakConfig.AdminPassword)
	} else {
		keycloakAdminPassword.SetText(generateRandomString(12))
	}
	keycloakHostName := tview.NewInputField().SetLabel("keycloak host name?").SetFieldWidth(30)
	keycloakHostName.SetText(oldConf.KeycloakConfig.HostName)
	keycloakHostPort := tview.NewInputField().SetLabel("keycloak host port?").SetFieldWidth(10)
	if oldConf.KeycloakConfig.HostPort != 0 {
		keycloakHostPort.SetText(strconv.Itoa(oldConf.KeycloakConfig.HostPort))
	} else {
		keycloakHostPort.SetText("50002")
	}
	keycloakHTTPSPort := tview.NewInputField().SetLabel("keycloak https port?").SetFieldWidth(10)
	if oldConf.KeycloakConfig.HttpsPort != 0 {
		keycloakHTTPSPort.SetText(strconv.Itoa(oldConf.KeycloakConfig.HttpsPort))
	} else {
		keycloakHTTPSPort.SetText("8444")
	}
	keycloakHTTPSTrustStorePassword := tview.NewInputField().SetLabel("keycloak https trust store password?").SetFieldWidth(30).SetMaskCharacter('*')
	if len(oldConf.KeycloakConfig.HttpsTrustStorePassword) > 0 {
		keycloakHTTPSTrustStorePassword.SetText(oldConf.KeycloakConfig.HttpsTrustStorePassword)
	}
	keycloakRealm := tview.NewInputField().SetLabel("keycloak realm name?").SetFieldWidth(30)
	if oldConf.KeycloakConfig.Realm == "" {
		keycloakRealm.SetText("ztsdp")
	} else {
		keycloakRealm.SetText(oldConf.KeycloakConfig.Realm)
	}
	keycloakClientID := tview.NewInputField().SetLabel("keycloak client id?").SetFieldWidth(30)
	keycloakClientID.SetText("ztna-sdp")
	keycloakClientID.SetDisabled(true)
	keycloakClientSecret := tview.NewInputField().SetLabel("keycloak client secret(optional)?").SetFieldWidth(30)
	keycloakClientSecret.SetText(oldConf.KeycloakConfig.ClientSecret)

	dbName := tview.NewInputField().SetLabel("database name?").SetFieldWidth(30)
	dbName.SetText("KEYCLOAK")
	dbAdmin := tview.NewInputField().SetLabel("database admin name?").SetFieldWidth(30)
	dbAdmin.SetText("root")
	dbAdminPassword := tview.NewInputField().SetLabel("database admin password?").SetFieldWidth(30).SetMaskCharacter('*')
	if len(oldConf.DatabaseConfig.DbAdminPassword) > 0 {
		dbAdminPassword.SetText(oldConf.DatabaseConfig.DbAdminPassword)
	} else {
		dbAdminPassword.SetText(generateRandomString(12))
	}

	divideLine1 := tview.NewInputField()
	divideLine1.SetDisabled(true)
	divideLine1.SetDrawFunc(func(screen tcell.Screen, x int, y int, width int, height int) (int, int, int, int) {
		// Draw a horizontal line across the middle of the divideLine.
		centerY := y + height/2
		for cx := x + 1; cx < x+width-1; cx++ {
			screen.SetContent(cx, centerY, tview.BoxDrawingsLightHorizontal, nil, tcell.Style{})
		}

		// Write some text along the horizontal line.
		tview.Print(screen, " Gateway side configuration ", x+1, centerY, width-2, tview.AlignCenter, tcell.ColorYellow)

		// Space for other content.
		return x + 1, centerY + 1, width - 2, height - (centerY + 1 - y)
	})

	divideLine := tview.NewInputField()
	divideLine.SetDisabled(true)
	divideLine.SetDrawFunc(func(screen tcell.Screen, x int, y int, width int, height int) (int, int, int, int) {
		// Draw a horizontal line across the middle of the divideLine.
		centerY := y + height/2
		for cx := x + 1; cx < x+width-1; cx++ {
			screen.SetContent(cx, centerY, tview.BoxDrawingsLightHorizontal, nil, tcell.Style{})
		}

		// Write some text along the horizontal line.
		tview.Print(screen, " Controller side configuration ", x+1, centerY, width-2, tview.AlignCenter, tcell.ColorYellow)

		// Space for other content.
		return x + 1, centerY + 1, width - 2, height - (centerY + 1 - y)
	})

	form = tview.NewForm().AddFormItem(role).AddFormItem(primaryIP).
		//AddFormItem(spaPort).
		AddFormItem(vpnPort).
		//AddFormItem(communicationPort).
		//AddFormItem(spaGlobalSecret).AddFormItem(controllerUUID).
		AddFormItem(policyServerIp).AddFormItem(policyServerAPIKey).
		AddFormItem(sshAllowedIp).
		AddFormItem(divideLine1).
		AddFormItem(controllerIP).AddFormItem(spaGlobalSecret).AddFormItem(controllerUUID).
		AddFormItem(divideLine).
		AddFormItem(gw1Alias).AddFormItem(gw1Domain).AddFormItem(gw1Ip).AddFormItem(gw1StandByIp).AddFormItem(gw1StandBySpaPort).AddFormItem(gw1StandByCommunicationPort).AddFormItem(gw1StandByVpnPort).
		AddFormItem(gw1IPPool).AddFormItem(gw1SPAPool).AddFormItem(gw1CommunicationPortPool).AddFormItem(gw1IPExpireTime).AddFormItem(gw1ThirdPartyDev).
		AddFormItem(gw2Alias).AddFormItem(gw2Domain).AddFormItem(gw2Ip).AddFormItem(gw2StandByIp).AddFormItem(gw2StandBySpaPort).AddFormItem(gw2StandByCommunicationPort).AddFormItem(gw2StandByVpnPort).
		AddFormItem(gw2IPPool).AddFormItem(gw2SPAPool).AddFormItem(gw2CommunicationPortPool).AddFormItem(gw2IPExpireTime).AddFormItem(gw2ThirdPartyDev).
		//AddFormItem(gwSpaPort).
		//AddFormItem(gwCommunicationPort).
		AddFormItem(gwVPNPort).
		AddFormItem(keycloakAdmin).
		//AddFormItem(keycloakAdminPassword).
		AddFormItem(keycloakHostName).
		//AddFormItem(keycloakHTTPSTrustStorePassword).
		//AddFormItem(keycloakHostPort).
		//AddFormItem(keycloakHTTPSPort).
		//AddFormItem(dbName).
		//AddFormItem(dbAdmin).
		//AddFormItem(dbAdminPassword).
		//AddFormItem(keycloakRealm).
		//AddFormItem(keycloakClientID).AddFormItem(keycloakClientSecret).
		AddButton("save", func() {
			// generate ztsdpd.conf
			sv, _ := strconv.Atoi(communicationPort.GetText())
			sp, _ := strconv.Atoi(spaPort.GetText())

			_, ro := role.GetCurrentOption()
			var gws []GatewayConfig

			comm, _ := strconv.Atoi(gwCommunicationPort.GetText())
			gw2IPExp, _ := strconv.Atoi(gw2IPExpireTime.GetText())

			gw1 := GatewayConfig{}
			gw1.Ip = gw1Ip.GetText()
			gw1.StandbyIp = gw1StandByIp.GetText()
			gw1.IPPool = gw1IPPool.GetText()
			gw1.Alias = gw1Alias.GetText()
			gw1.Domain = gw1Domain.GetText()
			gw1.SPAPortPool = gw1SPAPool.GetText()
			gw1.CommunicationPortPool = gw1CommunicationPortPool.GetText()
			gw1.ThirdPartyDevice = gw1ThirdPartyDev.IsChecked()
			gw1.SpaPort, _ = strconv.Atoi(gwSpaPort.GetText())
			gw1.CommunicationPort, _ = strconv.Atoi(gwCommunicationPort.GetText())
			gw1.VpnPort, _ = strconv.Atoi(gwVPNPort.GetText())
			gw1.PoolExpireTime, _ = strconv.Atoi(gw1IPExpireTime.GetText())
			gw1.StandbySPAPort, _ = strconv.Atoi(gw1StandBySpaPort.GetText())
			gw1.StandbyCommPort, _ = strconv.Atoi(gw1StandByCommunicationPort.GetText())
			gw1.StandbyVPNPort, _ = strconv.Atoi(gw1StandByVpnPort.GetText())

			gws = append(gws, gw1)

			gw2 := GatewayConfig{}
			if len(gw2Ip.GetText()) > 0 {
				gw2.Ip = gw2Ip.GetText()
				gw2.StandbyIp = gw2StandByIp.GetText()
				gw2.IPPool = gw2IPPool.GetText()
				gw2.PoolExpireTime = gw2IPExp
				gw2.Alias = gw2Alias.GetText()
				gw2.SpaPort, _ = strconv.Atoi(gwSpaPort.GetText())
				gw2.CommunicationPort = comm
				gw2.VpnPort, _ = strconv.Atoi(gwVPNPort.GetText())
				gw2.Domain = gw2Domain.GetText()
				gw2.SPAPortPool = gw2SPAPool.GetText()
				gw2.CommunicationPortPool = gw2CommunicationPortPool.GetText()
				gw2.ThirdPartyDevice = gw2ThirdPartyDev.IsChecked()
				gw2.PoolExpireTime, _ = strconv.Atoi(gw2IPExpireTime.GetText())
				gw2.StandbySPAPort, _ = strconv.Atoi(gw2StandBySpaPort.GetText())
				gw2.StandbyCommPort, _ = strconv.Atoi(gw2StandByCommunicationPort.GetText())
				gw2.StandbyVPNPort, _ = strconv.Atoi(gw2StandByVpnPort.GetText())
				gws = append(gws, gw2)
			}

			kcHostPort, _ := strconv.Atoi(keycloakHostPort.GetText())
			kcHTTPSPort, _ := strconv.Atoi(keycloakHTTPSPort.GetText())
			deviceVpnPort, _ := strconv.Atoi(vpnPort.GetText())

			devConf := DeviceConfig{
				Role:               ro,
				PrimaryIP:          primaryIP.GetText(),
				CommunicationPort:  sv,
				SpaPort:            sp,
				PolicyServerIP:     policyServerIp.GetText(),
				PolicyServerAPIKey: policyServerAPIKey.GetText(),
				SshAllowedIP:       sshAllowedIp.GetText(),
				VpnPort:            deviceVpnPort,
				ControllerIP:       controllerIP.GetText(),
			}

			if ro == "controller" {
				if oldConf.DeviceConfig.SpaGlobalSecret == "" {
					devConf.SpaGlobalSecret = generateRandomString(32)
				} else {
					devConf.SpaGlobalSecret = oldConf.DeviceConfig.SpaGlobalSecret
				}
				if oldConf.DeviceConfig.ControllerUUID == "" {
					devConf.ControllerUUID = uuid.New().String()
				} else {
					devConf.ControllerUUID = oldConf.DeviceConfig.ControllerUUID
				}
			} else {
				devConf.SpaGlobalSecret = spaGlobalSecret.GetText()
				devConf.ControllerUUID = controllerUUID.GetText()
			}

			data := Config{
				DeviceConfig:  devConf,
				GatewayConfig: gws,
				KeycloakConfig: KeycloakConfig{
					UseKeycloakAuth:         keycloakUse.IsChecked(),
					AdminId:                 keycloakAdmin.GetText(),
					AdminPassword:           keycloakAdminPassword.GetText(),
					HostName:                keycloakHostName.GetText(),
					HostPort:                kcHostPort,
					HttpsPort:               kcHTTPSPort,
					HttpsTrustStorePassword: keycloakHTTPSTrustStorePassword.GetText(),
					Realm:                   keycloakRealm.GetText(),
					ClientId:                keycloakClientID.GetText(),
					ClientSecret:            keycloakClientSecret.GetText(),
				},
				DatabaseConfig: DatabaseConfig{
					DbName:          dbName.GetText(),
					DbAdminId:       dbAdmin.GetText(),
					DbAdminPassword: dbAdminPassword.GetText(),
				},
			}

			yamlData, err := yaml.Marshal(data)
			ztsdpdConfFile, err := os.Create(ZTSDPD_CONF_PATH)
			if err != nil {
				fmt.Printf("%v", err)
			}
			defer ztsdpdConfFile.Close()
			_, err = ztsdpdConfFile.Write(yamlData)
			if err != nil {
				fmt.Printf("%v", err)
			}

			type Pair struct {
				Key   string
				Value string
			}

			if ro == "controller" {
				// generate kcadmin.conf
				kcadminConfFile, err := os.Create(KCADMIN_CONF_PATH)
				if err != nil {
					fmt.Printf("%v", err)
				}
				defer kcadminConfFile.Close()

				var kcadminConf []Pair
				kcadminConf = append(kcadminConf, Pair{"KEYCLOAK_URL", fmt.Sprintf("https://%s:%s", keycloakHostName.GetText(), keycloakHostPort.GetText())})
				kcadminConf = append(kcadminConf, Pair{"ADMIN_REALM", "master"})
				kcadminConf = append(kcadminConf, Pair{"ADMIN_USERNAME", keycloakAdmin.GetText()})
				kcadminConf = append(kcadminConf, Pair{"ADMIN_PASSWORD", keycloakAdminPassword.GetText()})
				kcadminConf = append(kcadminConf, Pair{"ADMIN_CLIENT_ID", "admin-cli"})
				kcadminConf = append(kcadminConf, Pair{"REALM", keycloakRealm.GetText()})
				kcadminConf = append(kcadminConf, Pair{"CLIENT_ID", keycloakClientID.GetText()})
				kcadminConf = append(kcadminConf, Pair{"CA_CERT_DIR", KEYCLOAK_CA_CERT_DIR})
				kcadminConf = append(kcadminConf, Pair{"CERT_DIR", KEYCLOAK_CERT_DIR})
				kcadminConf = append(kcadminConf, Pair{"CERT_USER_DIR", KEYCLOAK_USER_DIR})
				kcadminConf = append(kcadminConf, Pair{"CLIENT_CERT", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "client.crt")})
				kcadminConf = append(kcadminConf, Pair{"CLIENT_KEY", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "client.key")})
				kcadminConf = append(kcadminConf, Pair{"CA_CERT", fmt.Sprintf("%s/%s", KEYCLOAK_CA_CERT_DIR, "ca.pem")})
				kcadminConf = append(kcadminConf, Pair{"CA_KEY", fmt.Sprintf("%s/%s", KEYCLOAK_CA_CERT_DIR, "ca.key")})
				kcadminConf = append(kcadminConf, Pair{"CA_P12", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "server.p12")})
				kcadminConf = append(kcadminConf, Pair{"KC_CERT", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "server.crt")})
				kcadminConf = append(kcadminConf, Pair{"KC_CERT_CSR", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "server.csr")})
				kcadminConf = append(kcadminConf, Pair{"KC_CERT_KEY", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "server.key")})
				kcadminConf = append(kcadminConf, Pair{"KC_CERT_EXT", fmt.Sprintf("%s/%s", KEYCLOAK_CERT_DIR, "server.ext")})
				kcadminConf = append(kcadminConf, Pair{"PW_P12", keycloakHTTPSTrustStorePassword.GetText()})
				kcadminConf = append(kcadminConf, Pair{"KC_CLIENT_SECRET", keycloakClientSecret.GetText()})

				for _, confPair := range kcadminConf {
					_, err := fmt.Fprintf(kcadminConfFile, "%s=%s\n", confPair.Key, confPair.Value)
					if err != nil {
						fmt.Printf("%v", err)
					}
				}
			}

			// generation .env
			envFile, err := os.Create(".env")
			if err != nil {
				fmt.Printf("%v", err)
			}
			defer envFile.Close()

			var envConf []Pair

			if ro == "controller" {
				cmd := exec.Command("useradd", "mysql")
				cmd.Run()

				cmd = exec.Command("id", "-u", "mysql")
				uid, _ := cmd.CombinedOutput()
				envConf = append(envConf, Pair{"KC_MYSQL_UID", strings.TrimSpace(string(uid))})
				envConf = append(envConf, Pair{"KC_MYSQL_DB_NAME", dbName.GetText()})
				envConf = append(envConf, Pair{"KC_MYSQL_ADMIN", dbAdmin.GetText()})
				envConf = append(envConf, Pair{"KC_MYSQL_PASSWORD", dbAdminPassword.GetText()})
				envConf = append(envConf, Pair{"KC_HTTPS_PORT", keycloakHTTPSPort.GetText()})
				envConf = append(envConf, Pair{"KC_ADMIN", keycloakAdmin.GetText()})
				envConf = append(envConf, Pair{"KC_ADMIN_PASSWORD", keycloakAdminPassword.GetText()})
				envConf = append(envConf, Pair{"KC_HTTPS_PORT", keycloakHTTPSPort.GetText()})
				envConf = append(envConf, Pair{"KC_HTTPS_CERTIFICATE_FILE", fmt.Sprintf("/opt/keycloak/cert/server.crt")})
				envConf = append(envConf, Pair{"KC_HTTPS_CERTIFICATE_KEY_FILE", fmt.Sprintf("/opt/keycloak/cert/server.key")})
				envConf = append(envConf, Pair{"KC_HOSTNAME", keycloakHostName.GetText()})
				envConf = append(envConf, Pair{"KC_HOSTNAME_PORT", keycloakHostPort.GetText()})
				envConf = append(envConf, Pair{"KC_HTTPS_TRUST_STORE_PASSWORD", keycloakHTTPSTrustStorePassword.GetText()})
				envConf = append(envConf, Pair{"KC_TRUST_CA_FILE", "/opt/keycloak/cert/server.p12"})
				envConf = append(envConf, Pair{"KC_CLIENT_SECRET", keycloakClientSecret.GetText()})
				envConf = append(envConf, Pair{"KC_CLIENT_AUTH", "required"})
			}
			envConf = append(envConf, Pair{"SPA_SECRET", data.DeviceConfig.SpaGlobalSecret})
			envConf = append(envConf, Pair{"CONTROLLER_UUID", data.DeviceConfig.ControllerUUID})

			for _, confPair := range envConf {
				_, err := fmt.Fprintf(envFile, "%s=%s\n", confPair.Key, confPair.Value)
				if err != nil {
					fmt.Printf("%v", err)
				}
			}

			app.Stop()
		}).AddButton("close", func() {
		app.Stop()
	})
	form.SetBorder(true).SetTitle("ZTSDP configuration tool").SetTitleAlign(tview.AlignLeft)

	if err := app.SetRoot(form, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
