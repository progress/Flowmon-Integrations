#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
"""
This script is to allow Flowmon ADS notify about dangerous incdents to Veeam using API

Author: Jirka Knapek <jirka.knapek@progress.com>
Version 1.0
=========================================================================================
"""

import argparse
from doctest import debug
import logging
import requests
import sys
import json
import socket
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='/data/components/apps/log/veeam-api.log', format=LOGGING_FORMAT, level=logging.DEBUG)

def parse_arguments():
    parser = argparse.ArgumentParser(prog='veeam-api.py')
    parser.add_argument("-u", "--username", action='store', type=str, help="Username to authenticate for the API call.", default='username')
    parser.add_argument("-p", "--password", action='store', type=str, help="Password for the user.", default='password')
    parser.add_argument("-i", "--ip", action='store', type=str, help="IP address/hostname of the Veeam API gatewat", default='172.25.186.183:9419') 
    parser.add_argument("-t", "--test", action='store_true', help="Send test message")
    arguments = vars(parser.parse_args())
    return arguments

def login(ip, username, password):
    url = f"https://{ip}/api/oauth2/token"

    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
    }

    headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "x-api-version": "1.1-rev1"
    }
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False) 
        
        if response.status_code != 200:
            logging.error('Cannot autheticate to API {} : {} - {}'.format(ip, response.status_code, response.content))
            return False
        else:
            logging.info('API User successfuly authenticated to {}'.format(ip))
            data = response.json()['access_token']
            logging.debug(f"Received token: {data}")
            return data
    except(Exception, requests.TooManyRedirects) as error:
        logging.error('Too many redirects: {}'.format(error))
        return False
    except(Exception, requests.ConnectionError) as error:
        logging.error('Connection error: {}'.format(error))
        return False
    except(Exception, requests.Timeout) as error:
        logging.error('Timeout: {}'.format(error))
        return False

def message(ip, token, event):
    url = f"https://{ip}/api/v1/malwareDetection/events"
    date = datetime.datetime.strptime(event[2], "%Y-%m-%d %H:%M:%S").isoformat()
    if (len(event) < 15):
        event.append("n/a")
    details = f"Event ID {event[0]} - {event[4]} ({event[3]})\n Source: {event[10]}, User identity: {event[14]} - Targets: {event[12]}\n {event[7]}\n Perspective: {event[5]}, Data feed: {event[13]}"

    fqdn = "QAWINTEST01"
    if (event[14] == "n/a"):
        try:
            name, alias, addresslist = socket.gethostbyaddr(event[10])

            fqdn = name
        except socket.herror:
            logging.debug('Cannot translate the IP to FQDN')
    
    else:
        fqdn = event[14]   


    try:
        socket.inet_aton(event[10])

        payload = {
            "detectionTimeUtc": date,
            "machine": {
                "ipv4": event[10],
                "fqdn": fqdn
            },
            "details": details,
            "engine": "Flowmon ADS"
            }
        
    except socket.error:
        logging.debug("The source IP isn't IPv4")

        try:
            socket.inet_pton(socket.AF_INET6, event[10])

            payload = {
                "detectionTimeUtc": date,
                "machine": {
                    "ipv6": event[10],
                    "fqdn": fqdn
                },
                "details": details,
                "engine": "Flowmon ADS"
                }
        except:
            logging.error("The source isn't valid IPv6 either.")

    headers = {
        "Content-Type": "application/json",
        "x-api-version": "1.1-rev1",
        "Authorization": "Bearer {}".format(token)
    }

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)

        if response.status_code != 201:
            logging.debug('The payload is: {}'.format(payload))
            logging.error('Cannot talk to API {} : {} - {}'.format(ip, response.status_code, response.content))
            return False
        else:
            data = response.json()
            logging.debug(f"Received response: {data}")
    except(Exception, requests.TooManyRedirects) as error:
        logging.error('Too many redirects: {}'.format(error))
        return False
    except(Exception, requests.ConnectionError) as error:
        logging.error('Connection error: {}'.format(error))
        return False
    except(Exception, requests.Timeout) as error:
        logging.error('Timeout: {}'.format(error))
        return False

def main():
    logging.info('------- New run -------')
    args = parse_arguments()
    token = login(args["ip"], args["username"], args["password"])

    if (args['test'] == True):
        logging.debug('Sending test event now!')
        current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = [123, 1, current, "TEST", "Test Event", "Some Perspective", 6, "Event detail", 8, 9, "172.25.186.184", 11, "8.8.8.8", "Default", "QAWINTEST01"]
        message(args["ip"], token, event)
        exit()
    # This part is taking care of looping through the stdin until EOF (Ctrl+D)
    for line in sys.stdin:
        event = line.rstrip().split('\t')
        try:
            logging.info('ID {} - timestamp {} - source IP {}'.format(event[0],event[2],event[10]))
            message(args["ip"], token, event)
        except IndexError:
            logging.error('Incorrect number of parametres passed by ADS. {}'.format(event))

    logging.info('Everything is done')

if __name__ == "__main__":
       main()