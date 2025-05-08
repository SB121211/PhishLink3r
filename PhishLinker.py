
import requests
import socket
from bs4 import BeautifulSoup
import time
from colorama import Style,Fore,init
from urllib.parse import urlparse
import whois

sensitive_keywords = [
    # Urgency & Action-Oriented Words
    "urgent", "immediate", "action", "warning", "alert", "important", "expire", 
    "suspended", "lock", "expired", "expire-now", "reminder", "action-required", 
    "final-notice",

    # Authentication & Account-Related Words
    "login", "signin", "verify", "confirm", "account", "profile", "update", 
    "reset", "unlock", "recover", "forgot", "change-password", "confirm-your-account", 
    "recovery", "authenticate", "access", "secure-login",

    # Financial & Payment-Related Words
    "payment", "invoice", "checkout", "transaction", "billing", "card", "balance", 
    "credit", "banking", "bank", "wire-transfer", "refund", "subscription", "donation", 
    "deposit", "withdraw", "payment-method", "pay-now", "order-confirmation", "payable",

    # Offers & Rewards
    "claim", "gift", "bonus", "free", "reward", "prize", "offer", "exclusive", 
    "discount", "free-download", "win", "congratulations", "redeem", "get-your-prize",

    # Support & Helpdesk Terms
    "support", "customer-service", "helpdesk", "contact-us", "assistance", "service", 
    "help", "faq", "troubleshoot", "technical-support", "help-now", "live-chat",

    # Security & Threats
    "alert", "breach", "hacked", "compromised", "threat", "phishing", "scam", "malware", 
    "virus", "spyware", "trojan", "exploit", "keylogger", "ransomware", "warning",

    # Malicious Intent Indicators
    "crack", "keygen", "torrent", "free-download", "exe", "illegal", "pirate", 
    "malicious", "hack", "exploit", "stealth", "hack-tool", "free-crack","evil","devil",

    # Miscellaneous Suspicious Words
    "authenticate", "register", "cancel-subscription", "verify-now", "activation", 
    "confirm-now", "verify-identity", "account-locked", "access-denied", "check-status", 
    "update-now", "account-verified"
]

init(autoreset=True)

def banner():
    print(Style.BRIGHT + Fore.GREEN + "\n--PhishLinker--")
    print(Fore.BLUE + "\nWelcome to PhishLinker, a tool to stay secured throughout the internet!\n")
    print("-----------------------------------------------------------------------------")


def approach(url):
    response = requests.get(url=url)
    return response

def obtain_ip(url):
    n = urlparse(url)
    domain = n.hostname
    ip = socket.gethostbyname(domain)
    return ip

def ip_location(ip):
    url = f"https://ipwho.is/{ip}"
    response = requests.get(url)
    info = response.json()
    if info:
        return info
    else:
        print("Warning: IP info not available!")

def url_check(url):
    extension = url.split('.')
    leng = len(extension)
    n = urlparse(url)
    domain = n.hostname
    extension_list = ["com","org","edu","ir","gov","xyz","net","co","ru","cn","info","ai","io","shop","site","dev","app",
                      "us", "uk", "de", "fr", "ca", "au", "in", "ru", "cn", "br", "it", "es", "jp", "kr", "ir", "za", "tr",
                      "tk", "ml", "ga", "cf", "gq", "pw"]
    warns = 0

    if len(url) >= 74:
        print(Fore.RED + f"Warning: the url length is suspicious. ({len(url)} characters long!)")
        warns += 1
    time.sleep(1)

    if "https" not in url:
        print(Fore.RED + "Warning: the target does not have ssl certification(missing https)!")
        warns += 1
    time.sleep(1)

    n = False
    for i in extension_list:
        if i == extension[leng-1]:
            n = True
    if n == False:
        print(Fore.RED + f"Warning: unusual url extension(.{extension[leng-1]})!")
        warns += 1
    time.sleep(1)

    l = 0
    for x in url:
        if x == "%":
            l += 1
    if l / len(url) * 100 >= 5:
        print(Fore.RED + "Warning: the url seems to be suspiciously encoded!")
        warns += 1
    
    for i in sensitive_keywords:
        if i in url:
            print(Fore.RED + f"Warning: a sensitive keyword ({i}) has been found in the url!")
            warns += 1
    time.sleep(1)

    if leng >= 6:
        print(Fore.RED + "Warning: the target seems to indicate several subdomains!")
        warns += 1
    time.sleep(1)
    
    if domain and "xn--" in domain:
        print(Fore.RED + f"Warning(double alert): the domain seems to be punicoded ({domain})!")
        warns += 2
    return warns

def page_check(response):
    warns = 0
    info = response
    soap = BeautifulSoup(info.text,'html.parser')
    inputs = soap.find_all('input')
    links = soap.find_all('link')
    links2 = soap.find_all('a')
    for i in sensitive_keywords:
        if soap.title and soap.title.string and i.lower() in soap.title.string.lower():
            print(Fore.RED + f"Warning: a suspicious keyword was found in the title of the page! ({i})")
            warns += 1

    t = False
    for input in inputs:
        title = input.get('title')
        for i in sensitive_keywords:
            if title and i.lower() in title.lower():
                print(Fore.RED + f"Warning: a supicious keyword was found in an input in target's website! ({i})")
                t = True
    if t == True:
        warns += 1

    t = False
    for link in links:
        text = link.get('href')
        for i in sensitive_keywords:
            if text and i.lower() in text.lower():
                print(Fore.RED + f"Warning: be careful, a suspicious keyword was found in a link at the target's webpage: ({text})!")
                t = True
    if t == True:
        warns += 1

    t = False
    for link2 in links2:
        text = link2.get('href')
        for i in sensitive_keywords:
            if text and i.lower() in text.lower():
                print(Fore.RED + f"Warning: be careful, a suspicious keyword was found in a link at the target's webpage: ({text})!")
                t = True
    if t == True:
        warns += 1

    return warns

def whois_detail(url):
    domain = urlparse(url)
    domain = domain.hostname
    x = whois.whois(domain)
    if "registrar" in x and "creation_date" in x:
        print("Registrar: " + x.get("registrar"))
    else:
        print(Fore.RED + "Warning: The target seems to be new or out of whois details!")
        return 1
        


def main():
    banner()
    url = input("Enter the url to target's website: " + Fore.GREEN)
    response = approach(url)
    print(Style.RESET_ALL + "Approaching the target...")
    time.sleep(1)
    status = response.status_code
    if status == 200:
        print(Fore.GREEN + "Target is up, initiating the process...")
    
    print("-----------------------------------------------------------------------------")
    time.sleep(1)
    ip = obtain_ip(url)
    print("IP address: " + ip)
    location = ip_location(ip)
    continent = location.get('continent','continent not available!')
    print(f"Continent: {continent}")
    country = location.get('country','country not available!')
    print(f"Country: {country}")
    city = location.get('city','city not available!')
    print(f"City: {city}")
    time.sleep(1)

    print("-----------------------------------------------------------------------------")
    y = whois_detail(url)
    if y == 1:
        warns = url_check(url)  + page_check(response) + 1
    elif y != 1:
        warns = url_check(url)  + page_check(response)
    trust = 90 - (warns*10)
    print("-----------------------------------------------------------------------------")
    time.sleep(0.5)
    print(Fore.BLUE + "Getting results...")
    time.sleep(1)
    if warns == 0:
        print(Fore.GREEN + f"The webpage seems to be safe. (number of alerts found: {warns})")
        print(f"Trustability: {trust}% (never fully trust!)")
    elif warns <= 2:
        print(Fore.GREEN + f"The webpage seems to be trustable. (number of alerts found: {warns})")
        print(f"Trustability: {trust}% (never fully trust!)")
    elif warns == 3:
        print(Fore.YELLOW + f"The webpage seems to be suspicious. (number of alerts found: {warns})")
        print(f"Trustability: {trust}% (never fully trust!)")
    elif warns == 4:
        print(Fore.RED + f"The webpage seems to be malicious. (number of alerts found: {warns})")
        print(f"Trustability: {trust}%")
    elif warns >= 5 and warns < 7:
        print(Fore.RED + f"The webpage seems to be highly malicious. (number of alerts found: {warns})")
        print(f"Trustability: {trust}%")
    elif warns >= 7 and warns < 10:
        print(Fore.RED + f"Warning: Don't trust this webpage at all! (number of alerts found: {warns})")
        print(f"Trustability: {trust}%")
    elif warns >= 10:
        print(Fore.RED + f"Warning: Don't trust this webpage at all! (number of alerts found: {warns})")
        print(f"Trustability: 0%")

try:
    main()

except KeyboardInterrupt:
    print(Style.RESET_ALL + Fore.RED + Style.BRIGHT + "\n\nExitting...")

except requests.exceptions.ConnectionError:
    print(Style.RESET_ALL + Fore.RED + Style.BRIGHT + "Check your internet connection / Did you enter the url correctly?!")

except requests.exceptions.MissingSchema:
    print(Style.RESET_ALL + Fore.RED + Style.BRIGHT + "The target doesn't exist!")

except requests.exceptions.InvalidURL:
    print(Style.RESET_ALL + Fore.RED + Style.BRIGHT + "Invalid url!")

except requests.exceptions.InvalidURL:
    print(Style.RESET_ALL + Fore.RED + Style.BRIGHT + "Invalid url!")
