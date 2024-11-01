#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
"""
This script is to allow Flowmon ADS to trigger a IP blocking on the Powerscale Firewall
=========================================================================================
"""

import argparse
import logging
from urllib import response
import requests
import json
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='/data/components/apps/log/powerscale-api.log', format=LOGGING_FORMAT, level=logging.DEBUG)

def parse_arguments():
    parser = argparse.ArgumentParser(prog='make-backup.py')
    parser.add_argument("-u", "--username", action='store', type=str, help="Username to authenticate for the API call.", default='admin')
    parser.add_argument("-p", "--password", action='store', type=str, help="Password for the user.", default='2fourall')
    parser.add_argument("-i", "--ip", action='store', type=str, help="IP address/hostname of the Powerscale", default='10.67.53.188:8080') 
    parser.add_argument("-s", "--policy", action='store', required=True, type=str, help="Name of the policy") 
    parser.add_argument("-t", "--test", action='store_true', help="Run test to get session information and verify authentication.")
    arguments = vars(parser.parse_args())
    return arguments

def login(username, password, session):
    url = f"https://{IP}/session/1/session"

    payload = {
        "username": username,
        "password": password,
        "services": [ "platform" ],
    }
    try:
        response = session.post(url, data=json.dumps(payload)) 
        
        if response.status_code != 201:
            logging.error('Cannot autheticate to API {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            logging.info('API User successfuly authenticated to {}'.format(IP))
            # Set headers for CSRF protection. Without these two headers all further calls with be "auth denied"
            session.headers['referer'] = f"https://{IP}"
            session.headers['X-CSRF-Token'] = session.cookies.get('isicsrf')
            data = response.json()
            logging.debug(f"Received token: {data}")
            logging.debug(f"Received cookies: {session.cookies.get_dict()}")
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
    
def logout(session):
    url = f"https://{IP}/session/1/session"

    try:
        response = session.delete(url) 
        
        if response.status_code != 204:
            logging.error('Cannot logout form the machine {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            logging.info('Successfully logged out from {}'.format(IP))
            return True
    except requests.exceptions.RequestException as error:
        logging.error('Exception: {}'.format(error))
        return False

def test(session):
    url = f"https://{IP}/session/1/session"

    try:
        response = session.get(url)

        if response.status_code != 200:
            logging.error('Cannot talk to API {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            data = response.json()
            logging.debug(f"Received response: {data}")
    except requests.exceptions.RequestException as error:
        logging.error('Exception: {}'.format(error))
        return False
    
def check_policy(session, policy):
    url = f"https://{IP}/platform/16/network/firewall/policies"

    try:
        response = session.get(url)

        if response.status_code != 200:
            logging.error('Cannot talk to API {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            data = response.json()
            logging.debug('Got list of policies.')
    except requests.exceptions.RequestException as error:
        logging.error('Exception: {}'.format(error))
        return False
    
    for existing in data['policies']:
        if existing['name'] == policy:
            logging.debug("Policy exists".format(policy))
            return True
        
    return False

def check_rule(session, policy, adsip):
    url = f"https://{IP}/platform/16/network/firewall/policies/{policy}/rules"

    try:
        response = session.get(url)
        
        if response.status_code != 200:
            logging.error('Cannot check existing rules {} - {}'.format(response.status_code, response.content))
            return False
        else:
            logging.info('Successfully got firewall rules from device')
            data = response.json()
    except requests.exceptions.RequestException as error:
        logging.error('Exception: {}'.format(error))
        return False

    for existing in data['rules']:
        for rule_ip in existing['src_networks']:
            if rule_ip == adsip:
                logging.debug("IP {} is already configured".format(adsip))
                return True
    logging.debug("IP {} isn't configured in any rule yet".format(adsip))
    return False

def check_own(adsip):
    sep = ':'
    if adsip == IP.split(sep,1)[0]:
        logging.debug('IP {} is PowerScale IP, we are not going to block it'.format(adsip))
        return True
    else:
        logging.debug('IF {} does not belong to PowerScale'.format(adsip))
        return False
    
def create_rule(session, policy, event):
    url = f"https://{IP}/platform/16/network/firewall/policies/{policy}/rules?live=1&allow_renumbering=1"

    if len(event) < 15:
        description = 'Blocked at {} by {} ADS ID {}'.format(event[1], event[3], event[0])
    else:
        description = 'Blocked at {} by {} ADS ID {}, user ID {}'.format(event[1], event[3], event[0], event[14])


    payload = {
        "name": "ADS_{}".format(event[0]),
        "action": "deny",
        "protocol": "ALL",
        "index": 1,
        "description": description,
        "src_networks": [ "{}".format(event[10]) ],
    }

    try:
        response = session.post(url, data=json.dumps(payload))
        
        if response.status_code != 201:
            logging.error('Cannot create firewall rule {} : {} - {}'.format(event[10], response.status_code, response.content))
            return False
        else:
            logging.info('Successfully created Firewall rule to block IP {}'.format(event[10]))
            return True
    except requests.exceptions.RequestException as error:
        logging.error('Exception: {}'.format(error))
        return False

def main():
    global IP

    logging.info('------- New run -------')
    args = parse_arguments()
    
    IP = args["ip"]    
    headers = {
    "Content-Type": "application/json"
    }
    session = requests.Session()
    session.verify = False
    session.headers = headers
    login(args["username"], args["password"], session)

    if (args['test'] == True):
        logging.debug('Trying the API call now!')
        test(session)
        logout(session)
        exit()
    if not check_policy(session, args["policy"]):
        # Policy dosn't exists so we can finish here
        logging.debug('No action to be taken without correct policy.')
        exit(10)

    # This part is taking care of looping through the stdin until EOF (Ctrl+D)
    for line in sys.stdin:
        event = line.rstrip().split('\t')
        try:
            logging.info('ID {} - timestamp {} - source IP {}'.format(event[0],event[2],event[10]))
            if check_rule(session, args["policy"], event[10]):
                continue
            else:
                if check_own(event[10]):
                    #nothing to do here as IP is from PowerScale
                    continue
                else:
                    create_rule(session, args["policy"], event)
        except IndexError:
            logging.error('Incorrect number of parametres passed by ADS. {}'.format(event))

    logging.info('Everything is done')
    logout(session)

if __name__ == "__main__":
       main()