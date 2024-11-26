package main

import (
	"fmt"
	"github.com/rivo/tview"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
	. "ztsdp"
)

const (
	ZTSDPD_CONF = "/etc/ztsdpd.yaml"
)

func main() {
	var config Config

	if _, err := os.Stat(ZTSDPD_CONF); err == nil {
		file, _ := os.ReadFile(ZTSDPD_CONF)
		err = yaml.Unmarshal(file, &config)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	app := tview.NewApplication()

	alias := tview.NewInputField().SetLabel("Alias of the target device?").SetFieldWidth(30)
	newIp := tview.NewInputField().SetLabel("IP to change?").SetFieldWidth(30)
	newSPAPort := tview.NewInputField().SetLabel("SPA port to change?").SetFieldWidth(30)
	newCommPort := tview.NewInputField().SetLabel("Communication port to change?").SetFieldWidth(30)
	newVPNPort := tview.NewInputField().SetLabel("VPN port to change?").SetFieldWidth(30)

	gw1Info := fmt.Sprintf("Alias: %s\nStandby IP: %s\nStandby SPA port: %d\nStandby Communication port: %d\nStandby VPN port:%d",
		config.GatewayConfig[0].Alias, config.GatewayConfig[0].StandbyIp, config.GatewayConfig[0].SpaPort, config.GatewayConfig[0].CommunicationPort, config.GatewayConfig[0].VpnPort)
	textArea1 := tview.NewTextArea().SetLabel("gateway 1 information")
	textArea1.SetText(gw1Info, true).SetDisabled(true)

	textArea2 := tview.NewTextArea().SetLabel("gateway 2 information")
	if len(config.GatewayConfig) >= 2 {
		gw2Info := fmt.Sprintf("Alias: %s\nStandby IP: %s\nStandby SPA port: %d\nStandby Communication port: %d\nStandby VPN port:%d",
			config.GatewayConfig[1].Alias, config.GatewayConfig[1].StandbyIp, config.GatewayConfig[1].SpaPort, config.GatewayConfig[1].CommunicationPort, config.GatewayConfig[1].VpnPort)
		textArea2.SetText(gw2Info, true).SetDisabled(true)
	}

	form := tview.NewForm()
	form.AddFormItem(textArea1)
	if len(config.GatewayConfig) >= 2 {
		form.AddFormItem(textArea2)
	}
	form.AddFormItem(alias).AddFormItem(newIp).AddFormItem(newSPAPort).AddFormItem(newCommPort).AddFormItem(newVPNPort).
		AddButton("apply", func() {
			changerFile, err := os.Create(IPPortChangerFilePath)
			if err != nil {
				fmt.Printf("%v", err)
			}
			defer changerFile.Close()

			_, err = fmt.Fprintf(changerFile, "%s,%s,%s,%s,%s", alias.GetText(), newIp.GetText(), newSPAPort.GetText(), newCommPort.GetText(), newVPNPort.GetText())
			if err != nil {
				fmt.Printf("%v", err)
			}

			cmd := exec.Command("pkill", "-USR1", "ztsdpd")
			cmd.Run()

			app.Stop()
		})

	form.SetBorder(true).SetTitle("ZTSDP IP/Port changer tool").SetTitleAlign(tview.AlignLeft)
	if err := app.SetRoot(form, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
