import nmap
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import requests
import json
import threading
import socket
from pyfiglet import figlet_format
from luma.led_matrix.device import max7219
from luma.core.interface.serial import spi, noop
from luma.core.render import canvas
from PIL import Image, ImageDraw
import RPi.GPIO as GPIO
import time
from datetime import datetime
import httpagentparser
from user_agents import parse
from urllib.parse import parse_qs, urlparse

# Configuration for your Telegram Vendor Lookup API
TELEGRAM_TOKEN = 'YOUR TELEGARAM TOKEN' # Change This
TELEGRAM_CHAT_ID = 'YOUR TELEGRAM CHAT ID' # Change This
MAC_VENDOR_LOOKUP_URL = 'https://api.macvendors.com/'

# ASCII BANNER
print(figlet_format("HONEY PI By MXCALL", font="standard"))
# Credits
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
print("@                                                                                @")
print("@     NOTE: For educational use only. Use responsibly and at your own risk !     @")
print("@                                                                                @")
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")

# Server version and service name
SERVER_VERSION = "Apache/3.x"
SERVICE_NAME = "(Wordpress)"

# Set the GPIO mode
GPIO.setmode(GPIO.BCM)

# Define the buzzer pins
BUZZER_PIN_1 = 17  # Change this to the GPIO pin number you connected the first buzzer to
BUZZER_PIN_2 = 18  # Change this to the GPIO pin number you connected the second buzzer to

# Set the buzzer pins as output
GPIO.setup(BUZZER_PIN_1, GPIO.OUT)
GPIO.setup(BUZZER_PIN_2, GPIO.OUT)

# Dictionary to keep track of attempts per IP address
attempts_per_ip = {}

def control_buzzers(state):
    if state:
        # Turn on the buzzers
        GPIO.output(BUZZER_PIN_1, GPIO.HIGH)
        GPIO.output(BUZZER_PIN_2, GPIO.HIGH)
    else:
        # Turn off the buzzers
        GPIO.output(BUZZER_PIN_1, GPIO.LOW)
        GPIO.output(BUZZER_PIN_2, GPIO.LOW)

def display_dynamic_alert():
    # Create device with a single Cascaded MAX7219
    serial = spi(port=0, device=0, gpio=noop())
    device = max7219(serial, cascaded=1)
    device.contrast(16)  # Adjust the brightness (0 to 255)

    # Define the alert pattern (you can customize this pattern)
    alert_pattern = [
        [1, 1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 1],
        [1, 1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 1]
    ]

    # Define the blank pattern
    blank_pattern = [[0]*8 for _ in range(8)]

    # Function to draw the pattern on the LED matrix
    def draw_alert(draw, pattern):
        for y, row in enumerate(pattern):
            for x, col in enumerate(row):
                draw.point((x, y), fill="white" if col else "black")

    # Blink the alert pattern for about 3 seconds
    for _ in range(15):  # Adjust this number as needed
        with canvas(device) as draw:
            draw_alert(draw, alert_pattern)
        time.sleep(0.1)
        with canvas(device) as draw:
            draw_alert(draw, blank_pattern)
        time.sleep(0.1)

    # Clear the LED matrix
    with canvas(device) as draw:
        draw_alert(draw, blank_pattern)

# Function to send messages to Telegram
def send_telegram_message(message):
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    data = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'MarkdownV2'}
    try:
        requests.post(url, data=data)
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send message to Telegram: {e}")

# Function to get the MAC address vendor information
def get_mac_vendor(mac_address):
    try:
        response = requests.get(MAC_VENDOR_LOOKUP_URL + mac_address)
        if response.status_code == 200:
            return response.text
        else:
            return 'Unknown'
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get MAC vendor information: {e}")
        return 'Unknown'

# Custom handler for HTTP requests
class HoneypotHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION
    sys_version = SERVICE_NAME

    def handle_request(self, method, post_data=None):
        access_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        visitor_ip = self.client_address[0]
        if visitor_ip in attempts_per_ip:
            attempts_per_ip[visitor_ip] += 1
        else:
            attempts_per_ip[visitor_ip] = 1
        attempt_counter = attempts_per_ip[visitor_ip]
        
        mac_address = get_mac_address(visitor_ip)
        mac_vendor = get_mac_vendor(mac_address) if mac_address != 'Unknown' else 'Unknown'
        user_agent_string = self.headers.get('User-Agent', 'Unknown')
        
        # Enhanced User-Agent parsing
        user_agent = httpagentparser.detect(user_agent_string)
        parsed_ua = parse(user_agent_string)
        
        # Extract device type, OS, and browser details from the parsed user agent
        device_type = parsed_ua.device.family
        os_family = parsed_ua.os.family
        os_version = parsed_ua.os.version_string
        browser_family = parsed_ua.browser.family
        browser_version = parsed_ua.browser.version_string
        
        # Extract login credentials if available
        login_data = {}
        if post_data:
            login_data = parse_qs(post_data)
        
        # Turn off the buzzers when a visitor accesses the honeypot
        control_buzzers(False)
        
        # Display dynamic alert sign on LED matrix when honeypot is triggered
        display_dynamic_alert()
        control_buzzers(True)
        request_info = {
            'Visitor IP': visitor_ip,
            'MAC Address': mac_address,
            'MAC Vendor': mac_vendor,
            'Device Type': device_type,
            'Operating System': f"{os_family} {os_version}",
            'Browser': f"{browser_family} {browser_version}",
            'User-Agent Raw': user_agent_string,
            'Requested Path': self.path,
            'Method': method,
            'Attempt Number': attempt_counter,
            'Access Time': access_time,
            'Login Data': login_data
        }
        
        message = f"*Alert: Honeypot Triggered*\n```json\n{json.dumps(request_info, indent=2)}\n```"
        send_telegram_message(message)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open('login.html', 'rb') as file:
            self.wfile.write(file.read())

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        self.handle_request('POST', post_data)

    # Add additional methods to handle other HTTP methods as needed

    def log_message(self, format, *args):
        pass

# Function to get the MAC address using python-nmap
def get_mac_address(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sn')
        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                return nm[host]['addresses']['mac']
        return 'Unknown'
    except nmap.PortScannerError as e:
        logging.error(f"Failed to scan for MAC address: {e}")
        return 'Unknown'

# CLI for server control
def server_cli(httpd):
    while True:
        command = input("Enter \"Stop\" to halt the server: ")
        if command.lower() == 'stop':
            # Turn on the buzzers before exiting
            control_buzzers(True)
            # Clean up the GPIO pins
            GPIO.cleanup()
            httpd.shutdown()
            print("Server is stopping...")
            break

if __name__ == '__main__':
    control_buzzers(True)
    server_address = ('', 80)
    httpd = HTTPServer(server_address, HoneypotHTTPRequestHandler)
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    server_cli(httpd)
