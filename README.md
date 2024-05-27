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
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install nmap -y
git clone https://github.com/MXCAlldev/HoneyPi.git
cd HoneyPi/
sudo pip3 install -r requirements.txt
```
#### NOTE: RUN Command As ROOT and make sure that You Enable SPI Interface
#### Here Interface Options => SPI => Choose enable => Finish
```bash
sudo sudo raspi-config
```

## How to run it
```bash
sudo python3 main.py
```

## How to Integrating HoneyPi with WordPress
### Set Up Your Honeypot Server:
* Ensure that your Honeypi is set up and running. This server will capture and analyze suspicious requests.
* To further protect your WordPress login panel by redirecting unauthorized users based on their IP address, you can add a custom function to your theme's functions.php file:
  * Open the functions.php file of your theme or create a custom plugin.
  * Add the following PHP code at The End:
```bash
function check_ip_and_redirect() {
    $allowed_ips = ['your_allowed_ip1', 'your_allowed_ip2']; // Replace with your allowed IPs
    $visitor_ip = $_SERVER['REMOTE_ADDR'];

    if (!in_array($visitor_ip, $allowed_ips)) {
        
        wp_redirect('http://your-honeypot-server.com'); // HoneyPi IP Address
        exit;
    }
}

add_action('login_init', 'check_ip_and_redirect');

```
#### NOTE:
* "your_allowed_ip1" and "your_allowed_ip2": Replace with the IP address from which legitimate requests to WordPress should not be redirected to the honeypot server.
* "your-honeypot-server.com": Replace with the URL of your Honeypi server.

## Possible Modification

Customize the server settings, GPIO pin assignments, and LED matrix patterns in the configuration section of the script.

## Disclaimer
The HONEYPI is a Web Honeypot Server developed for educational purposes and should be used ethically and responsibly. The creator does not endorse nor accept responsibility for any improper or unlawful use of this software. Users are advised to implement this project in a secure and controlled environment. By using HONEYPI, you agree to do so at your own risk and hold yourself accountable for any consequences that arise from its use.
