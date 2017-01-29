package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/jrossiter/arlo-go"
)

type ArloConfig struct {
	Username string
	Password string
}

func main() {
	mode := flag.String("m", "", "Mode: arm|disarm")
	verbose := flag.Int("v", 0, "Verbose")
	flag.Parse()

	var internalMode string

	config := ArloConfig{}

	content, err := ioutil.ReadFile("config.toml")
	if err != nil {
		log.Fatal(err)
	}

	_, err = toml.Decode(string(content), &config)
	if err != nil {
		log.Panic(err)
	}

	switch *mode {
	case "arm":
		internalMode = arlo.ModeDeviceArm
	case "disarm":
		internalMode = arlo.ModeDeviceDisarm
	default:
		fmt.Println("Invalid mode")
		return
	}

	err = ArmDisarm(config.Username, config.Password, internalMode, *verbose == 1)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func ArmDisarm(username, password, mode string, verbose bool) error {
	a := arlo.NewArlo()
	a.Username = username
	a.Password = password
	a.Verbose = verbose

	err := a.Login()
	if err != nil {
		log.Println("Login failed")
		return err
	}

	log.Println("Login OK")

	a.GetDevices()

	bs, err := a.GetBasestation()
	if err != nil {
		log.Println("GetBasestation failed")
		return err
	}

	switch mode {
	case arlo.ModeDeviceArm:
		err = a.Arm(bs.DeviceID, bs.XCloudID)
	case arlo.ModeDeviceDisarm:
		err = a.Disarm(bs.DeviceID, bs.XCloudID)
	}

	if err != nil {
		return err
	}

	return a.Logout()
}
