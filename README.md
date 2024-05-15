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
2. Execute these Commands

```console
HoneyPi@raspberrypi:~/Honeypi $ sudo pip install -r requirements.txt
```
## How to run it
#### NOTE: RUN Command As ROOT USER

```console
HoneyPi@raspberrypi:~/Honeypi $ sudo python3 main.py
```

## How to Integrating HoneyPi with WordPress
### Set Up Your Honeypot Server:
* Ensure that your Honeypi is set up and running. This server will capture and analyze suspicious requests.
### Customize ".htaccess":
* Navigate to the root directory of your WordPress installation.
* Open or create the .htaccess file.
* Add the following code snippet to the ".htaccess" file:
```console
# BEGIN Custom HoneyPi Integration
<IfModule mod_rewrite.c>
RewriteEngine On

# Exclude requests to your honeypot script to prevent redirection loop
RewriteCond %{REQUEST_URI} !^/honeypot.php

# Redirect requests for wp-login.php and wp-admin to the honeypot server
RewriteCond %{REQUEST_URI} ^(.*)?wp-login\.php(.*)$ [OR]
RewriteCond %{REQUEST_URI} ^(.*)?wp-admin$
RewriteCond %{REMOTE_ADDR} !^YOUR_LEGITIMATE_IP_ADDRESS$
RewriteRule ^(.*)$ http://your-HoneyPi-server.com/$1 [P,L]
</IfModule>
# END Custom Honeypot Integration
```
#### NOTE:
* YOUR_LEGITIMATE_IP_ADDRESS: Replace with the IP address from which legitimate requests to WordPress should not be redirected to the honeypot server.
* your-honeypot-server: Replace with the URL of your Honeypi server.

## Possible Modification

Customize the server settings, GPIO pin assignments, and LED matrix patterns in the configuration section of the script.

## Disclaimer
The HONEYPI is a Web Honeypot Server developed for educational purposes and should be used ethically and responsibly. The creator does not endorse nor accept responsibility for any improper or unlawful use of this software. Users are advised to implement this project in a secure and controlled environment. By using HONEYPI, you agree to do so at your own risk and hold yourself accountable for any consequences that arise from its use.
