#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
"""
This script is to allow Flowmon ADS notify about incdents to MS Teams channel using
Workflow automation and new formats abailable since ADS 12.5

=========================================================================================
"""

import argparse
import sys
import json
import socket
import requests
import logging

WEBHOOK = 'https://<Your-URL-here>'
FLOWMON = '<Your-Flowmon>'
LOG_FILE = '/data/components/apps/log/teams-webhook.log'

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename=LOG_FILE, format=LOGGING_FORMAT, level=logging.INFO)

def parse_arguments():
    parser = argparse.ArgumentParser(prog='teams-webhook.py')
    parser.add_argument("-f", "--flowmon", action='store', type=str, help="IP address or URL of the local Flowmon appliance", default=FLOWMON)
    parser.add_argument("-w", "--webhook", action='store', type=str, help="Microsoft Teams Webhook URL", default=WEBHOOK)
    parser.add_argument("-t", "--test", action='store_true', help="Send test message")
    parser.add_argument("-j", "--json", action='store_true', help="Use new JSON format")
    # Use uknow here to run even though there are some unrecongizes arguments like -j with parametre as that is how ADS is running it
    arguments, uknown = parser.parse_known_args()
    return vars(arguments)

def send_to_teams(data):    
    ads = f"https://{FLOWMON}/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList|eventDetail%5B%5D*"

    headers = {'Content-Type': 'application/json'}

    if not data['userIdentity']:
        data['userIdentity'] = 'N/A'

    logging.info(f"{data['id']} - type {data['type']} - source {data['source']}") 
    logging.debug("In the dictionary {}".format(data))
    
    data = json.dumps({
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl" : None,
                "content": {
                    "type": "AdaptiveCard",
                    "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.5",

                    "body": [
                        {
                            "type": "Container",
                            "width": "Wide",
                            "items": [
                                {"type": "TextBlock", "text": f"**{data['timestamp']}** Flowmon ADS detected a new event", "wrap": True},
                                {"type": "TextBlock", "text": f"**{data['typeDesc']}** ({data['type']})", "weight": "Bolder", "size": "Large", "style": "heading", "wrap": True},
                                {"type": "TextBlock", "text": f"Priority: **{data['severity']}**, Event ID [{data['id']}]({ads}{data['id']})", "wrap": True},
                                {"type": "TextBlock", "text": f"Source: **{get_hostname(data['source'])}**, User identity: {data['userIdentity']}", "wrap": True},
                                {"type": "TextBlock", "text": f"Targets: {get_targets(data['targets'])}", "wrap": True},
                                {"type": "TextBlock", "text": f"{data['detail']}", "wrap": True},
                                {"type": "TextBlock", "text": f"Perspective: **{data['perspective']}**, Data feed: **{data['netFlowSource']}**", "wrap": True}
                            ]
                        }
                    ]
                }
            }
        ]
    })
    logging.debug("JSON {}".format(data))

    response = requests.post(WEBHOOK, data=data, headers=headers)

    if response.status_code != 202:
        logging.error('Cannot talk to Webhook: {} - {}'.format(response.status_code, response.content))
        return False
    else:
        logging.debug(f"Received response: {response}")

# Try to get name translation for an IP address
def get_hostname(ip):
    try:
        hostname,alias,addreslist = socket.gethostbyaddr(ip)
        hostname = f"{hostname} ({ip})"
    except socket.herror:
        hostname = ip

    return hostname

# Get translations for target IPs
def get_targets(targets):
    targets = str.split(targets, ', ')
    translated = ''
    for target in targets:
        if not translated:
            translated = get_hostname(target)
        else:
            translated += ', ' + get_hostname(target)
    
    return translated

def main():
    global WEBHOOK, FLOWMON

    args = parse_arguments() 

    if (args['test'] == True):
        logging.debug('Sending test event now!')
        data = {'timestamp' : '8/28/2023 10:13',
                'typeDesc'  : 'SSH attack',
                'type' : 'SSHDICT',
                'severity' : 'Critical',
                'id': '532028',
                'source' : '10.10.9.31',
                'targets' : '10.100.28.40',
                'detail' : 'Attack from a single attacker has been detected. This attack was unsuccessful. Current targets: 1, attempts: 8, upload: 29.09 KiB, maximal upload: 3.66 KiB; total targets: 1, attempts: 33, upload: 90.92 KiB, maximal upload: 3.66 KiB',
                'perspective' : 'Security Issues',
                'netFlowSource' : 'LAN',
                'userIdentity' : ''
                }
        
        send_to_teams(data)
        exit()

    elif (args['json'] == True):
        # This part is taking care of looping through the stdin until EOF (Ctrl+D)    
        logging.debug("---- Starting JSON run ----")
        for line in sys.stdin:
            json_input = line
            data_dict = json.loads(json_input)

            # If there is no perspective then we are going to work with IDS event and process it
            if not 'timestamp' in data_dict:
                data = {'timestamp' : data_dict['firstSeen'],
                    'typeDesc'  : data_dict['category'],
                    'type' : 'IDSP',
                    'severity' : data_dict['severity'],
                    'id': data_dict['id'],
                    'source' : data_dict['srcIp'],
                    'targets' : data_dict['dstIp'],
                    'detail' : data_dict['signatureName'],
                    'perspective' : data_dict['logSourceInterface'],
                    'netFlowSource' : data_dict['logSourceIp'],
                    'userIdentity' : ''
                    }
                data_dict = data

            # when we are working with standad ADS event we don't need to do anything just perform normal steps
            send_to_teams(data_dict)
    else:
        # This part is taking care of looping through the stdin until EOF (Ctrl+D) and using the older format of events separated by tab
        logging.debug("---- Starting standard run ----")
        for line in sys.stdin:
            array = line.strip().split('\t')

        receivedLength = len(array)
        
        logging.debug('Received #{} : {}'.format(receivedLength, array))
        # Check for length of received details to make sure we work with ADS detection
        if receivedLength >= 15:
            if 0 <= 16 <= len(array):
                array.append('')

            data = {'timestamp' : array[1],
                    'typeDesc'  : array[4],
                    'type' : array[3],
                    'severity' : array[8],
                    'id': array[0],
                    'source' : array[12],
                    'targets' : array[14],
                    'detail' : array[9],
                    'perspective' : array[7],
                    'netFlowSource' : array[15],
                    'userIdentity' : array[16]
                    }
        else:
            # Try to porecess as IDS event
            data = {'timestamp' : array[1],
                    'typeDesc'  : array[12],
                    'type' : 'IDSP',
                    'severity' : array[13],
                    'id': array[0],
                    'source' : array[3],
                    'targets' : array[5],
                    'detail' : array[9],
                    'perspective' : array[11],
                    'netFlowSource' : array[10],
                    'userIdentity' : ''
                    }
        
        send_to_teams(data)

    logging.info("---- Everything completed ----")

if __name__ == "__main__":
       main()
