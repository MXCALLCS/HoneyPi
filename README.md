# HONEYPI Honeypot Server

<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/WEB_Honeypot.png" />

#### HONEYPI is an Internal honeypot system that lures and analyzes cyber attackers. It uses a decoy, gathers information, alerts security teams, and signals onsite staff with alarms.

# Network Topology
<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/Network%20Topology.png" />

## Features

* Decoy WordPress Administration Page: A fake login page that mimics the real WordPress admin interface to attract attackers.
* Information Capture: Collects detailed information about attackers, including IP Address, MAC address, etc...
* MAC Vendor Lookup: Uses an API to identify the vendor of the attacker's network interface.
* Real-Time Alerts: Sends instant notifications to a Telegram group of security administrators or SOC team members when an attack is detected.
* Visual and Audible Alerts: Triggers two buzzers and displays an alert message on an 8x8 LED matrix to notify people nearby of a potential security incident.
* Extensible and customizable to fit various security needs.

## Requirement
* Python 3.x 
* Raspberry pi
* Buzzers x2
* LED Matrix 8x8
* Jumper Wires
* Breadboard (to Connect All the Components)

## The Circuits

<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/Diagram.png" />

## Installation
1. Clone the repository
2. Execute this Commands

```console
HoneyPi@raspberrypi:~/Honeypi $ pip install -r requirements.txt
```
## How to run it?
#### (NOTE RUN Command As ROOT USER)

```console
HoneyPi@raspberrypi:~/Honeypi $ sudo python3 main.py
```

## Possible Modification

Customize the server settings, GPIO pin assignments, and LED matrix patterns in the configuration section of the script.

## Disclaimer
The HONEYPI is a Web Honeypot Server developed for educational purposes and should be used ethically and responsibly. The creator does not endorse nor accept responsibility for any improper or unlawful use of this software. Users are advised to implement this project in a secure and controlled environment. By using HONEYPI, you agree to do so at your own risk and hold yourself accountable for any consequences that arise from its use.
