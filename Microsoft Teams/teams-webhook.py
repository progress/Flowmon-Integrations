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
    # Use unknown here to run even though there are some unrecognized arguments like -j with parameter as that is how ADS is running it
    arguments, unknown = parser.parse_known_args()
    return vars(arguments)

def send_to_teams(data, webhook, flowmon):
    ads = f"https://{flowmon}/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList|eventDetail%5B%5D*"

    headers = {'Content-Type': 'application/json'}

    if not data['userIdentity']:
        data['userIdentity'] = 'N/A'

    logging.info(f"{data['id']} - type {data['type']} - source {data['source']}")
    logging.debug("In the dictionary {}".format(data))

    payload = json.dumps({
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
    logging.debug("JSON {}".format(payload))

    try:
        response = requests.post(webhook, data=payload, headers=headers, timeout=30)
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send to webhook: {e}")
        return False

    if response.status_code != 202:
        logging.error('Cannot talk to Webhook: {} - {}'.format(response.status_code, response.content))
        return False
    else:
        logging.debug(f"Received response: {response}")
        return True

# Try to get name translation for an IP address
def get_hostname(ip):
    try:
        hostname,alias,addreslist = socket.gethostbyaddr(ip)
        hostname = f"{hostname} ({ip})"
    except (socket.herror, socket.gaierror, OSError):
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

    WEBHOOK = args['webhook']
    FLOWMON = args['flowmon']

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
        
        send_to_teams(data, WEBHOOK, FLOWMON)
        exit()

    elif (args['json'] == True):
        # This part is taking care of looping through the stdin until EOF (Ctrl+D)    
        logging.debug("---- Starting JSON run ----")
        for line in sys.stdin:
            try:
                data_dict = json.loads(line)
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse JSON input: {e} -- line: {line.strip()}")
                continue

            # If there is no timestamp then we are going to work with an IDS event and process it
            if 'timestamp' not in data_dict:
                data_dict = {
                    'timestamp'     : data_dict.get('firstSeen', 'N/A'),
                    'typeDesc'      : data_dict.get('category', 'N/A'),
                    'type'          : 'IDSP',
                    'severity'      : data_dict.get('severity', 'N/A'),
                    'id'            : data_dict.get('id', 'N/A'),
                    'source'        : data_dict.get('srcIp', 'N/A'),
                    'targets'       : data_dict.get('dstIp', 'N/A'),
                    'detail'        : data_dict.get('signatureName', 'N/A'),
                    'perspective'   : data_dict.get('logSourceInterface', 'N/A'),
                    'netFlowSource' : data_dict.get('logSourceIp', 'N/A'),
                    'userIdentity'  : ''
                }

            # when we are working with standard ADS event we don't need to do anything just perform normal steps
            send_to_teams(data_dict, WEBHOOK, FLOWMON)
    else:
        # This part is taking care of looping through the stdin until EOF (Ctrl+D) and using the older format of events separated by tab
        logging.debug("---- Starting standard run ----")
        for line in sys.stdin:
            array = line.strip().split('\t')
            receivedLength = len(array)

            logging.debug('Received #{} : {}'.format(receivedLength, array))
            # Check for length of received details to make sure we work with ADS detection
            if receivedLength >= 15:
                if len(array) <= 16:
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
                # Try to process as IDS event (needs at least 14 fields)
                if receivedLength < 14:
                    logging.error('Received too few fields ({}) to process as IDS event, skipping.'.format(receivedLength))
                    continue

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

            send_to_teams(data, WEBHOOK, FLOWMON)

    logging.info("---- Everything completed ----")

if __name__ == "__main__":
       main()
