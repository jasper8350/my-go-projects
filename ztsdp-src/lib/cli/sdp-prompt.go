package main

import (
	"bufio"
	"fmt"
	"github.com/abiosoft/ishell/v2"
	"os"
	"slices"
	"sort"
	"strings"
)

var COMMAND_LIST = []string{"kc_admin", "kc_admin_password", "kc_hostname", "kc_hostname_port", "kc_trust_store_password",
	"zt_role", "zt_spa_port", "zt_svc_port", "zt_svc_portvpn", "zt_script_path", "zt_gw_ip", "zt_gw_port", "zt_gw_svc_port",
	"zt_port_timeout", "zt_ssh_access", "zt_policy_server", "zt_vpn_port_timeout"}

func FileOpenReplace(c *ishell.Context, key string, value string) {
	f, err := os.OpenFile(".env", os.O_CREATE|os.O_RDWR, os.FileMode(0644))
	if err != nil {
		c.Printf(err.Error())
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var text []string
	find := false

	for scanner.Scan() {
		if len(strings.Split(scanner.Text(), "=")) >= 2 {
			if strings.Split(scanner.Text(), "=")[0] == strings.ToUpper(key) {
				text = append(text, fmt.Sprintf("%s=%s\n", strings.ToUpper(key), value))
				find = true
				c.Printf("%s settings have been modified. VALUE=%s\n", key, value)
			} else {
				text = append(text, fmt.Sprintf("%s\n", scanner.Text()))
			}
		}
	}
	if find == false {
		text = append(text, fmt.Sprintf("%s=%s\n", strings.ToUpper(key), value))
		c.Printf("%s settings have been inserted. VALUE=%s\n", key, value)
	}

	f.Seek(0, 0)
	sort.Strings(text)
	w := bufio.NewWriter(f)
	_, err = w.WriteString(strings.Join(text, ""))
	if err != nil {
		c.Println(err.Error())
	}
	err = w.Flush()
	if err != nil {
		c.Println(err.Error())
	}
	return
}

func ReplaceEnv(c *ishell.Context) {
	if len(c.Args) == 0 {
		c.Println("An argument is required.")
		return
	}
	if slices.Contains(COMMAND_LIST, c.Cmd.Name) {
		FileOpenReplace(c, c.Cmd.Name, c.Args[0])
	} else {
		c.Println("Command does not exist.")
	}
}

func main() {
	shell := ishell.New()

	shell.Println("\n\nztsdp interactive shell\ntype help")

	shell.AddCmd(&ishell.Cmd{
		Name: "show",
		Help: "Show all settings",
		Func: func(c *ishell.Context) {
			str, err := os.ReadFile(".env")
			if err != nil {
				c.Println(err.Error())
			}
			c.Println(string(str))
		},
	})

	for _, command := range COMMAND_LIST {
		shell.AddCmd(&ishell.Cmd{
			Name: command,
			Help: fmt.Sprintf("set %s", command),
			Func: ReplaceEnv,
		})
	}

	shell.Run()
}
