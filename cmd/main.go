package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

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

	config := ArloConfig{}
	content, err := ioutil.ReadFile("config.toml")
	if err != nil {
		log.Fatal(err)
	}
	_, err = toml.Decode(string(content), &config)
	if err != nil {
		log.Panic(err)
	}

	var internalMode string
	switch *mode {
	case "arm":
		internalMode = arlo.ModeDeviceArm
	case "disarm":
		internalMode = arlo.ModeDeviceDisarm
	default:
		log.Fatal("Invalid mode")
	}

	err = ArmDisarm(config.Username, config.Password, internalMode, *verbose == 1)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(0)
}

func ArmDisarm(username, password, mode string, verbose bool) error {
	a := arlo.NewClient()
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
