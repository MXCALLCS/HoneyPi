# HONEYPI Honeypot Server

<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/WEB_Honeypot.png" />

### HONEYPI is a sophisticated honeypot server designed to simulate vulnerabilities, detect unauthorized access, and alert system administrators.

## Features

* Simulates a vulnerable Apache server running WordPress to attract potential attackers.
* Sends real-time alerts to a Telegram bot when the honeypot detects activity.
* Displays dynamic alert patterns on an LED matrix to signal intrusion attempts.
* Utilizes buzzers to provide an audible alert during security events.
* Retrieves MAC address vendor information to identify the hardware manufacturer of the intruder's device.
* Extensible and customizable to fit various security needs.
## Installation

1. Clone the repository
2. Execute this Commands

```console
HoneyPi@raspberrypi:~/Honeypi $ pip install -r requirements.txt
```
## How to run it ?
#### (NOTE RUN Command As ROOT USER)

```console
HoneyPi@raspberrypi:~/Honeypi $ sudo python3 main.py
```

## Modification

Customize the server settings, GPIO pin assignments, and LED matrix patterns in the configuration section of the script.

## Disclaimer
The HONEY PI Honeypot Server is developed for educational purposes and should be used ethically and responsibly. The creator,does not endorse nor accept responsibility for any improper or unlawful use of this software. Users are advised to implement this project in a secure and controlled environment. By using HONEY PI, you agree to do so at your own risk and hold yourself accountable for any consequences that arise from its use.
