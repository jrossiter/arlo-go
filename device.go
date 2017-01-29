package arlo

const (
	DeviceTypeBasestation = "basestation"
	DeviceTypeCamera      = "camera"
)

// Device represents a basestation or camera.
type Device struct {
	UserID     string `json:"userId"`
	DeviceID   string `json:"deviceId"`
	UniqueID   string `json:"uniqueId"`
	DeviceType string `json:"deviceType"`
	DeviceName string `json:"deviceName"`
	XCloudID   string `json:"xCloudId"`
}

func (d Device) IsBasestation() bool {
	return d.DeviceType == DeviceTypeBasestation
}

func (d Device) IsCamera() bool {
	return d.DeviceType == DeviceTypeCamera
}
