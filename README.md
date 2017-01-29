# Arlo-go 
>An SDK for arming and disarming Netgear's Arlo camera system.

This library offers a basic method to quickly arm and disarm the system via CLI.
This was created due to how slow it is to arm / disarm the system via the Arlo Android app.

The CLI app and code example can be found in the `cmd` directory.

## Disclaimer
This project was made for convenience, and practise of the `Go` language. It does not come with unit tests or guarantees that it will work for non-default set ups. Use at your own discretion. 

## Getting started with the CLI app

### Build
```
cd cmd && build -o arlo main.go
```

### Config set up
```
cp config.toml.sample config.toml

// Enter your Arlo details in the config file
```

### Args
```
Mode: -m <arm|disarm>
```

### Arm / Disarm
```
// Arm
./arlo -m arm

// Disarm
./arlo -m disarm
```
