TeslaWearKey
===

An app for Android Wear that allows the user to use their WearOS watch to unlock, lock, and drive supported Tesla vehicles.

Based on HCE, ,the watch emulates as a Tesla Key Card to interact with the vehicle.

---
### Features
* Unlock / Lock your Tesla Model 3 or Y.
* Android KeyStore protected keys
* No internet access or bluetooth required
* Based on Tesla Key Card protocol

### Dependencies
* NFC-enabled WearOS watch
* Tested on Samsung Galaxy Watch 4 Classic LTE and Galaxy Watch 6

### Usage Guide
* Enable Developer mode on your watch
* Connect to watch via ADB
* Side-load apk file found in releases via ADB
* Use existing key card to load watch in the vehicle system
* Test extensively to ensure watch works effectively.
* TIP: The side of the Galaxy Watches contains the NFC antenna.
* TIP 2: The app must be in an ACTIVE state for NFC to work. It can easily go in to standby.

### References
* [GaussKeyCard](https://github.com/darconeous/gauss-key-card)
* [TKC Protocol](https://gist.github.com/darconeous/2cd2de11148e3a75685940158bddf933) by [@darconeous](https://github.com/darconeous)
