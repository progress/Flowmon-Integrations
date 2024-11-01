#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script is to allow Flowmon ADS block user on ProLion CryptoSpike

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
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='/data/components/apps/log/cryptospike-api.log', format=LOGGING_FORMAT, level=logging.DEBUG)

def parse_arguments():
    parser = argparse.ArgumentParser(prog='cryptospike-block-user.py')
    parser.add_argument("-u", "--username", action='store', type=str, help="Username to authenticate for the API call.", default='sysadm')
    parser.add_argument("-p", "--password", action='store', type=str, help="Password for the user.", default='Inv3a-t3ch123')
    parser.add_argument("-i", "--ip", action='store', type=str, help="IP address/hostname of the CryptoSpike", default='10.100.24.10') 
    arguments = vars(parser.parse_args())
    return arguments

def login(username, password, session):
    url = f"https://{IP}/api/v1/Server/auth/login"

    payload = {
        "username": username,
        "password": password,
    }

    headers = {
        "Content-Type": "application/json",
        "accept": "application/json"
    }

    session.headers.update(headers)
    
    try:
        response = session.post(url, data=json.dumps(payload)) 
        
        if response.status_code != 200:
            logging.error('Cannot autheticate to API {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            logging.info('API User successfuly authenticated to {}'.format(IP))
            data = response.json()['token']
            logging.debug(f"Received token lifetime: {response.json()['lifetime']}")
            headers['authorization'] = "Bearer {}".format(data)
            session.headers.update(headers)
            return data
    except requests.exceptions.RequestException as error:
        logging.error('Error: {}'.format(error))
        return False
    
def logout(session):
    url = f"https://{IP}/api/v1/Server/auth/logout"

    try:
        response = session.get(url) 
        
        if response.status_code != 200:
            logging.error('Cannot logout this session {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            logging.info('API session succesfully logged out of {}'.format(IP))
            return True
    except requests.exceptions.RequestException as error:
        logging.error('Error: {}'.format(error))
        return False

# Function to search for User ID we would need this information to block the user on CryptoSpike platform    
def find_sid(session, source):
    current = int(datetime.datetime.now().timestamp())
    previous = int((datetime.datetime.now() - datetime.timedelta(minutes=30)).timestamp())
    url = f"https://{IP}/api/v1/audit/dashboard/file-activity/table?=&page=0&size=50&start={previous}&end={current}"

    payload = {
        "path":"",
        "users":[],
        "actions":[],
        "fileType":[],
        "extensions":[],
        "clusters":[],
        "servers":[],
        "shares":[],
        "volumes":[],
        "ips": [source],
        "blocked":[]
    }

    try:        
        response = session.post(url, data=json.dumps(payload))
        
        if response.status_code != 200:
            logging.error('Cannot receive File Activity about IP {} : {} - {}'.format(source, response.status_code, response.content))
            return False
        else:
            logging.info('Looking for File Activity for IP {}'.format(source))
            data = response.json()['items']
            if data:
                # We have data to process
                # Lets store first ID to match it with the rest
                user_id = data[0]['id']
                for user in data:
                    if user_id != user['id']:
                        # We have nother User ID for the same IP. We cannot take any action now
                        logging.info('User ID is not unique for the IP address. No action to be taken')
                        return False
                    
                # We didn't find another UID using the same IP at this time
                logging.debug('We found UID {}'.format(user_id))
                return user_id
            else:
                # We don't have any data
                logging.debug(f"No file acitity found for the IP {source}")
                return False
    except requests.exceptions.RequestException as error:
        logging.error('Error: {}'.format(error))
        return False
    
def block_user(session, user_id, event):    
    url = f"https://{IP}/api/v1/analyzer/events/users/access"
    
    if (len(event) < 15):
        event.append("n/a")
    details = f"Flowmon ADS Event ID {event[0]} - {event[4]} ({event[3]})\n Source: {event[10]}, User identity: {event[14]} - Targets: {event[12]}\n {event[7]}\n Perspective: {event[5]}, Data feed: {event[13]}"

    payload = {
        "userId":user_id,
        "userIdType":"WINDOWS",
        "userAccessState":"BLOCKED",
        "comment": details
    }
    
    try:
        response = session.post(url, data=json.dumps(payload)) 
        
        if response.status_code != 200:
            logging.error('Cannot block user {} : {} - {}'.format(IP, response.status_code, response.content))
            return False
        else:
            logging.info('User {} successfully blocked'.format(user_id))
            return True
    except requests.exceptions.RequestException as error:
        logging.error('Error: {}'.format(error))
        return False
    
def search_user(session, user_name):
    url = f"https://{IP}/api/v1/audit/users?page=0&size=20&search={user_name}&blocked=false&orderBy=&sortDescending=false"
    
    try:
        response = session.get(url) 
        
        if response.status_code != 200:
            logging.error('Cannot search for the user {} : {} - {}'.format(user_name, response.status_code, response.content))
            return False
        else:
            data = response.json()['items']
            if data:
                # We have found some information abour user_name
                logging.debug('We found UID {} for {}'.format(data['userId'], user_name))
                return data['userId']
            else:
                # We don't have any result for the user_name               
                logging.debug('We cannot find UID for {}'.format(user_name))
                return False
            
    except requests.exceptions.RequestException as error:
        logging.error('Error: {}'.format(error))
        return False


def main():
    global IP
    logging.info('------- New run -------')
    args = parse_arguments()
    IP = args["ip"]
    session = requests.Session()
    session.verify = False
    token = login(args["username"], args["password"], session)

    if token:
        # This part is taking care of looping through the stdin until EOF (Ctrl+D)
        for line in sys.stdin:
            event = line.rstrip().split('\t')
            try:
                logging.info('ID {} - timestamp {} - source IP {}'.format(event[0],event[2],event[10]))
                user_id = find_sid(session, event[10])
                if user_id:
                    # We got a user ID form the FileActivity
                    block_user(session, user_id, event)
                else:
                    # When we have user identity configured we try to search for UserID based on the user_name we have from Flowmon User Identity
                    if (len(event) == 15) and event[14] != "n/a":
                        user_id = search_user(session, event[14])
                        if user_id:
                            block_user(session, user_id, event)
            except IndexError:
                logging.error('Incorrect number of parametres passed by ADS. {}'.format(event))
                
    logout(session)
    logging.info('--------- Everything is done --------')

    
if __name__ == "__main__":
       main()