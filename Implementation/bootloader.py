### ANDREW RUCKS
### April 25, 2026
### IAS490 - Advanced Topics in Information Assurance & Security
### Project - "Demonstrating Secure OTA Update Principles with Python"

### This script is a "bootloader" for a mock internet-of-things (IoT) device.
### I made it to demonstrate the principles of secure over-the-air (OTA) updating.
### It checks for updates, downloads update files, verifies integrity, and has automatic rollback just in case.
### Updates, in the form of Python scripts, are downloaded over HTTPS and are additionally encrypted.
### The update files are digitally signed and verified as well.
### Note: Update server and code signing infrastructure not included :P

import subprocess
import requests
import shutil
import json
import time
import re
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509

SRVRPATH = "https://uds.otademo.net" #path to update delivery server (otademo.net is a LOCAL domain)
DEMONSTRATION_MODE = True #adds pauses

# global vars set during runtime
current_installed_version = ""
decryption_key = ""
update_version = ""
update_signature = ""
path_to_update = ""
downloaded_file = ""
abort_update = False #triggered by errors in the update pipeline

def main():

    debug("\nIOT THERMOSTAT DEVICE", 2)

    # load stored variables from disk
    global current_installed_version
    global decryption_key
    with open("current_version_number", "r") as file:
        current_installed_version = file.read()
    with open("key", "r") as file:
        decryption_key = base64.b64decode(file.read())

    # secure OTA update
    if is_update_available() == True:
        download_update()

        if verify_update() == True:
            install_update()
            boot(True)

    else:
        boot()
    return
  

def boot(new_ver_test=False):
    debug("Booting...", 2)
    try:
        subprocess.run(["python3", "current_version.py"], check=True)
    except subprocess.CalledProcessError:
        debug("Device crashed!", 1)
        
        if new_ver_test:
            revert_to_old()
            boot()
    return


def is_update_available():
    debug("Current software version: " + current_installed_version + "\n", 1)
    debug("Checking for updates...", 2.5)
    try:
        latest_available_version = requests.get(SRVRPATH + "/latest_software_version.txt").text.replace("\n", "")
    except:
        debug("\tProblem with connecting to the update server?\n")
        return False
    
    if not re.match(r"^\d+\.\d+\.\d+$", latest_available_version):
        debug("\tProblem with update server?\n")
        return False

    civsplit = current_installed_version.split(".")
    lavsplit = latest_available_version.split(".")
    if (current_installed_version != latest_available_version):
        if ((lavsplit[0] > civsplit[0]) or (lavsplit[1] > civsplit[1]) or (lavsplit[2] > civsplit[2])):
        
            fetch_metadata(latest_available_version)
            debug("\tUpdate is available: version " + update_version + "\n", 1)
            return True  

    debug("\tUpdate not needed.\n", 1)
            
def fetch_metadata(ver):
    global path_to_update
    global update_version
    global update_signature
    
    try:
        request = requests.get(SRVRPATH + "/metadata/"+ ver + ".json")
    except:
        debug("\tProblem with connecting to the update server?\n")
        abort_update = True #ceases further update functions
        return
        
    raw = json.loads(request.text)
    
    path_to_update = decrypt_content(raw["path"], raw["nonce"], raw["tag"])
    update_version = raw["ver"]
    update_signature = base64.b64decode(raw["signature"])
    return
    

def download_update():
    if abort_update:
        return
    
    global downloaded_file
    debug("Downloading...", 2.5)
    request = requests.get(SRVRPATH + path_to_update)
    
    raw = json.loads(request.text)
    
    downloaded_file = decrypt_content(raw["code"], raw["nonce"], raw["tag"])
    debug("\tComplete!\n", 1)
    return
    

def verify_update():
    if abort_update:
        return
        
    debug("Verifying integrity...", 2.5)
    with open("code_verification.crt", "rb") as file:
    
        cert = x509.load_pem_x509_certificate(file.read())
        
        pubkey = cert.public_key()
        
        try:
            pubkey.verify(update_signature, downloaded_file.encode("utf-8"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            debug("\tPassed!\n", 1)
            return True
            
        except:
            debug("\tSignature mismatch - update failed!\n", 1)
            return False


def install_update():
    if abort_update:
        return

    debug("Installing update... ", 2.5)

    # copy current_version to old_version
    shutil.copy("current_version.py", "old_version.py")
    
    # write new version to current_version
    with open("current_version.py", "w", encoding="utf-8") as file:
        file.write(downloaded_file)
        
    # update version number
    shutil.copy("current_version_number", "old_version_number")
    with open("current_version_number", "w", encoding="utf-8") as file:
        file.write(update_version)
        
    debug("\tComplete!\n", 1)
    return
    
    
def revert_to_old():
    debug("Restoring previous version...", 1)
    
    # copy old_version to current_version
    shutil.copy("old_version.py", "current_version.py")
    
    # revert version number
    shutil.copy("old_version_number", "current_version_number")
    return
    
    
def decrypt_content(content, nonce, tag):
        
    decryptor = AES.new(decryption_key, AES.MODE_GCM, nonce=base64.b64decode(nonce))
    
    return decryptor.decrypt_and_verify(base64.b64decode(content), base64.b64decode(tag)).decode()
    

def debug(text, eep_time=0):
    print(text)
    if DEMONSTRATION_MODE:
        time.sleep(eep_time)
    return
    

if __name__ == "__main__":
    main()
    
