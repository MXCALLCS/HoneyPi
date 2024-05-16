<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/WEB_Honeypot.png" />

#### HONEYPI is an Internal honeypot system that lures and analyzes cyber attackers. It uses a decoy, gathers information, alerts security teams, and signals onsite staff with alarms.

### [Read before you dive into the Project](https://github.com/MXCAlldev/HoneyPi#disclaimer)

# Network Topology
<img src="https://github.com/MXCAlldev/HoneyPi/blob/main/Network%20Topology.png" />

## Features

* Decoy WordPress Administration Page: Provides a fake login page that resembles the genuine WordPress admin interface, attracting potential attackers to interact with the honeypot.
* Information Capture: Collects comprehensive details about attackers, including their IP addresses, MAC addresses, device types, operating systems, browsers, user-agent strings, login attempts, and access timestamps.
* MAC Vendor Lookup: Utilizes an API to identify the vendor of the attacker's network interface based on their MAC address, providing insights into the origin of the attack.
* Real-Time Alerts: Sends instant notifications to a designated Telegram group of security administrators or SOC team members whenever suspicious activity is detected, facilitating prompt response to potential threats.
* Raspberry Pi Integration: Designed to run on a Raspberry Pi, providing scalability and ease of maintenance for deployment in different network environments.
* Visual and Audible Alerts: Triggers two buzzers and displays a distinct alert message on an 8x8 LED matrix, providing both visual and audible cues to notify nearby individuals of a potential security incident.
* Attempt Tracking: Keeps track of the number of login attempts per IP address, enabling the identification of repetitive or persistent attackers
* Customizable and Extensible: Offers flexibility for customization and extension to suit various security needs, allowing security professionals to adapt the honeypot according to their specific requirements.

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
```console
HoneyPi@raspberrypi:~ $ sudo apt update && sudo apt upgrade -y
HoneyPi@raspberrypi:~ $ git clone https://github.com/MXCAlldev/HoneyPi.git
HoneyPi@raspberrypi:~ $ cd HoneyPi/
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
