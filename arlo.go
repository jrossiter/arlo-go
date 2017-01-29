package arlo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"

	"github.com/r3labs/sse"
)

const baseURL = "https://arlo.netgear.com"

// Errors
var (
	ErrRequestFailedStatusNotOK = errors.New("request failed")
	ErrRequestUnsuccessful      = errors.New("request unsuccessful")
	ErrNotLoggedIn              = errors.New("not logged in yet")
	ErrNoBasestationFound       = errors.New("no basestation found")
	ErrNoCamerasFound           = errors.New("no cameras found")
	ErrRequestUnauthorized      = errors.New("401 unauthorized")
)

// Device modes
const (
	ModeDeviceArm    = "mode1"
	ModeDeviceDisarm = "mode0"
)

type Arlo struct {
	// For initial login
	Username string
	Password string
	UserID   string

	// For request authorization
	Token string

	HTTPClient   *http.Client
	Devices      []Device
	EventStreams map[string]*EventStream

	Verbose bool
}

func NewArlo() *Arlo {
	cookieJar, _ := cookiejar.New(nil)

	return &Arlo{
		HTTPClient:   &http.Client{Jar: cookieJar},
		EventStreams: make(map[string]*EventStream),
	}
}

func (a *Arlo) getCommonHeaders() map[string]string {
	return map[string]string{
		"DNT":           "1",
		"Host":          "arlo.netgear.com",
		"Referer":       "https://arlo.netgear.com",
		"Authorization": a.Token,
	}
}

func (a *Arlo) applyCommonHeaders(req *http.Request) {
	for key, value := range a.getCommonHeaders() {
		req.Header.Add(key, value)
	}
}

func (a *Arlo) hasLoggedIn() bool {
	return a.Token != ""
}

// Login logs into Arlo.
func (a *Arlo) Login() error {
	type loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type loginResponse struct {
		Data struct {
			UserID        string `json:"userId"`
			Email         string `json:"email"`
			Token         string `json:"token"`
			PaymentID     string `json:"paymentId"`
			Authenticated int    `json:"authenticated"`
			AccountStatus string `json:"accountStatus"`
			SerialNumber  string `json:"serialNumber"`
			CountryCode   string `json:"countryCode"`
			TOCUpdate     bool   `json:"tocUpdate"`
			PolicyUpdate  bool   `json:"policyUpdate"`
			ValidEmail    bool   `json:"validEmail"`
			Arlo          bool   `json:"arlo"`
		} `json:"data"`
		Success bool `json:"success"`
	}

	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(loginRequest{a.Username, a.Password})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", baseURL+"/hmsweb/login", b)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return ErrRequestUnauthorized
		default:
			a.verbose("Status code:", resp.StatusCode)
			return ErrRequestFailedStatusNotOK
		}
	}

	respBody := loginResponse{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return err
	}

	if !respBody.Success {
		return ErrRequestUnsuccessful
	}

	a.UserID = respBody.Data.UserID
	a.Token = respBody.Data.Token

	return nil
}

// Logout logs out of Arlo and clears vars.
func (a *Arlo) Logout() error {
	req, err := http.NewRequest("PUT", baseURL+"/hmsweb/logout", nil)
	if err != nil {
		return err
	}
	a.applyCommonHeaders(req)

	resp, err := a.HTTPClient.Do(req)
	resp.Body.Close()

	// Clear vars
	a.Token = ""
	a.UserID = ""
	cookieJar, _ := cookiejar.New(nil)
	a.HTTPClient.Jar = cookieJar

	return err
}

// GetDevices retrieves available devices from the Arlo servers.
func (a *Arlo) GetDevices() ([]Device, error) {
	if !a.hasLoggedIn() {
		return nil, ErrNotLoggedIn
	}

	type deviceRequest struct {
		UnixTS int64 `json:"t"`
	}

	type deviceResponse struct {
		Devices []Device `json:"data"`
		Success bool     `json:"success"`
	}

	ts := time.Now().UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))

	req, err := http.NewRequest("GET", baseURL+fmt.Sprintf("/hmsweb/users/devices?t=%d", ts), nil)
	if err != nil {
		return nil, err
	}
	a.applyCommonHeaders(req)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, ErrRequestUnauthorized
		default:
			a.verbose("Status code:", resp.StatusCode)
			return nil, ErrRequestFailedStatusNotOK
		}
	}

	respBody := deviceResponse{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return nil, err
	}

	if !respBody.Success {
		return nil, ErrRequestUnsuccessful
	}

	a.Devices = respBody.Devices

	return respBody.Devices, nil
}

// GetBasestation attempts to retrieve the basestation device from memory.
// GetDevices() should be called beforehand.
func (a *Arlo) GetBasestation() (*Device, error) {
	for _, device := range a.Devices {
		if device.IsBasestation() {
			return &device, nil
		}
	}
	return nil, ErrNoBasestationFound
}

// GetCameras attempts to retrieve a list of camera devices from memory.
// GetDevices() should be called beforehand.
func (a *Arlo) GetCameras() ([]Device, error) {
	var cameras []Device
	for _, device := range a.Devices {
		if device.IsCamera() {
			cameras = append(cameras, device)
		}
	}

	if len(cameras) == 0 {
		return nil, ErrNoCamerasFound
	}

	return cameras, nil
}

// Subscribe connects to the event stream for the given device.
func (a *Arlo) Subscribe(deviceID, xCloudID string) error {
	var err error

	_, ok := a.EventStreams[deviceID]
	if !ok {
		c := sse.NewClient(baseURL + fmt.Sprintf("/hmsweb/client/subscribe?token=%s", a.Token))
		c.Connection = a.HTTPClient
		c.Headers = a.getCommonHeaders()

		es := NewEventStream()
		es.SSEClient = c
		es.Verbose = a.Verbose

		errCh := make(chan error, 1)

		go func() {
			errCh <- es.Listen()
		}()

	Loop:
		for {
			select {
			case err = <-errCh:
				a.verbose("error occurred", err)
				break Loop
			default:
				if es.Connected {
					a.verbose("event stream connected!")
					a.EventStreams[deviceID] = es

					break Loop
				}
			}

			time.Sleep(time.Millisecond * 500)
		}

		if err != nil {
			return err
		}

		err = a.Register(deviceID, xCloudID)
	}

	return err
}

func (a *Arlo) Register(deviceID, xCloudID string) error {
	//{"action":"set","resource":"subscriptions/"+self.user_id+"_web",
	// "publishResponse":"false","properties":{"devices":[device_id]}})

	properties := make(map[string][]string)
	properties["devices"] = []string{deviceID}

	np := NotifyPayload{
		Action:          "set",
		Resource:        fmt.Sprintf("subscriptions/%s_web", a.UserID),
		PublishResponse: false,
		Properties:      properties,
	}

	_, err := a.Notify(deviceID, xCloudID, np)
	if err != nil {
		a.verbose("Register error")
		return err
	}

	a.EventStreams[deviceID].Registered = true

	return nil
}

type NotifyPayload struct {
	Action          string      `json:"action,omitempty"`
	Resource        string      `json:"resource,omitempty"`
	PublishResponse bool        `json:"publishResponse,omitempty"`
	Properties      interface{} `json:"properties,omitempty"`

	TransID string `json:"transId"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func (a *Arlo) getTransID() string {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)

	e := random.Float64() * math.Pow(2, 32)

	ms := time.Now().UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))

	return fmt.Sprintf("web!%s!%s", strings.ToLower(floatToHex(e)), strconv.Itoa(int(ms)))
}

func (a *Arlo) Notify(deviceID, xCloudID string, payload NotifyPayload) (string, error) {
	payload.TransID = a.getTransID()
	payload.From = fmt.Sprintf("%s_web", a.UserID)
	payload.To = deviceID

	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf(baseURL+"/hmsweb/users/devices/notify/%s", deviceID), b)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("xCloudId", xCloudID)

	a.applyCommonHeaders(req)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return "", ErrRequestUnauthorized
		default:
			a.verbose("Status code:", resp.StatusCode)
			return "", ErrRequestFailedStatusNotOK
		}
	}

	return payload.TransID, nil
}

func (a *Arlo) Arm(deviceID, xCloudID string) error {
	err := a.Subscribe(deviceID, xCloudID)
	if err != nil {
		return err
	}

	// {"action":"set","resource":"modes","publishResponse":"true",
	// "properties":{"active":"mode1"}})

	properties := make(map[string]string)
	properties["active"] = ModeDeviceArm

	np := NotifyPayload{
		Action:          "set",
		Resource:        "modes",
		PublishResponse: true,
		Properties:      properties,
	}

	_, err = a.Notify(deviceID, xCloudID, np)
	return err
}

func (a *Arlo) Disarm(deviceID, xCloudID string) error {
	err := a.Subscribe(deviceID, xCloudID)
	if err != nil {
		return err
	}

	// {"action":"set","resource":"modes","publishResponse":"true",
	// "properties":{"active":"mode0"}})

	properties := make(map[string]string)
	properties["active"] = ModeDeviceDisarm

	np := NotifyPayload{
		Action:          "set",
		Resource:        "modes",
		PublishResponse: true,
		Properties:      properties,
	}

	_, err = a.Notify(deviceID, xCloudID, np)
	return err
}

func floatToHex(x float64) string {
	var result []byte
	quotient := int(x)
	fraction := x - float64(quotient)

	for quotient > 0 {
		quotient = int(x / 16)
		remainder := int(x - (float64(quotient) * 16))

		if remainder > 9 {
			result = append([]byte{byte(remainder + 55)}, result...)
		} else {
			for _, c := range strconv.Itoa(int(remainder)) {
				result = append([]byte{byte(c)}, result...)
			}
		}

		x = float64(quotient)
	}

	if fraction == 0 {
		return string(result)
	}

	result = append(result, '.')

	for fraction > 0 {
		fraction = fraction * 16
		integer := int(fraction)
		fraction = fraction - float64(integer)

		if integer > 9 {
			result = append(result, byte(integer+55))
		} else {
			for _, c := range strconv.Itoa(int(integer)) {
				result = append(result, byte(c))
			}
		}
	}

	return string(result)
}

func (a *Arlo) verbose(params ...interface{}) {
	if a.Verbose {
		log.Println(params...)
	}
}
