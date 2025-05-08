# PhishLinker

## Overview
A command based tool for basic validation of untrusted links using a deny by default and heuristic analysis approach to evaluate given url and content stored in the webpage and prevent phishing attacks.
it also utilizes sockets to obtain ip and api calls from "ipwho.is" service through user device to pull information about the target's url and geolocation.

## Features
- URL check for strange or suspicious behaviour
- URL check for possible encoding
- Page check for suspicious keywords containing 
- Output IP and geolocation of the target's server
- Checking whois details and registrar info
- Display possible threats and warnings
- Display results and calculate trustability precentage based on number of warnings

## Installation
1. Install python3
2. Install dependencies:
`pip3 install -r requirements.txt`
4. Download the script:
`git clone https://github.com/SB121211/PhishLink3r.git`

## Usage
`python3 PhishLinker.py`
1. Enter your target's url (e.g. https://{target}.com)
2. Wait for program to evaluate data and output the result

## Disclaimer
- API and Data Usage: The program uses the "ipwho.is" API and Python's sockets library to obtain information about the target's IP address and geolocation. These requests are made from the user's device and may interact with the target's server. By using this tool, you agree to abide by the terms and conditions of these third-party services.

- Ethical Use: PhishLinker is designed for ethical and security purposes only. It should only be used in accordance with ethical guidelines and applicable laws. Unauthorized scanning or probing of websites without permission is prohibited and may violate privacy and security regulations.

- Limitations and Accuracy: PhishLinker uses heuristic analysis and various methods for evaluating potential phishing threats. However the results are not guaranteed to detect all phishing attempts or security risks. Users should not fully trust the results and the tool should not be relied upon as the sole means of evaluating a website's safety.
