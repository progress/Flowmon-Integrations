#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script is to help with blocking of bad actors on Loadmaster using blocklists

Author: Jirka Knapek <jirka.knapek@progress.com>
Version 1.0
=========================================================================================
"""

import argparse
import logging
import requests
import sys
import subprocess
import shlex
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='/data/components/apps/log/lm-api.log', format=LOGGING_FORMAT, level=logging.DEBUG)


def parse_arguments():
    parser = argparse.ArgumentParser(prog='lm-block.py')
    parser.add_argument("-k", "--key", action='store', type=str, help="REST API key to use for authentication", required=True)
    parser.add_argument("-i", "--ip", action='store', type=str, help="IP address/hostname of the Loadmaster", required=True)
    parser.add_argument("-v", "--vs", action='store', type=int, help="Virtual service ID")
    arguments = vars(parser.parse_args())
    return arguments

def run_command(command_line):
    arguments = shlex.split(command_line)
    p = subprocess.Popen(arguments, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    std_data = p.communicate()
    output = (p.returncode, std_data[0].decode("utf8"), std_data[1].decode("utf8"))
    return output

def block(args, event):
    url = f"https://{args['ip']}/accessv2"

    if isinstance(args['vs'], int):
        # VS ID is set so just block at the WS
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(args['key']),
                    "addvs": "block",
                    "vs": "{}".format(args['vs']),
                    "addr": event['source'],
                    "comment": "ADS ID {} - {}".format(event['id'], event['type'])
                    }
    else:
        # No VS ID so we are blocking global
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(args['key']),
                    "add": "block",
                    "addr": event['source'],
                    "comment": "ADS ID {} - {}".format(event['id'], event['type'])
                    }
    response = requests.post(url, json=payload, verify=False)

    if response.status_code != 200:
        logging.error('Cannot talk to API {} : {} - {}'.format(args['ip'], response.status_code, response.content))
        return False
    else:
        data = response.json()
        # Add IP to DB so it could be removed later
        command = f"/home/flowmon/lm-mitigation/lm-timeout.py -a {event['source']} -e {event['id']}"
        if isinstance(args['vs'], int):
            command = command + f" -v {args['vs']}"
        
        logging.debug(command)
        output = run_command(command)
        if output[0] == 0:
            logging.debug(f"Received response: {data}")
        else:
            logging.debug(output)

def main():
    logging.info('------- New run -------')
    args = parse_arguments()

    # This part is taking care of looping through the stdin until EOF (Ctrl+D)
    for line in sys.stdin:
        event = line.rstrip().split('\t')
        receivedLength = len(event)
        
        logging.debug('Received #{} : {}'.format(receivedLength, event))
        # Check for length of received details to make sure we work with ADS detection
        if receivedLength >= 15:
            if 0 <= 16 <= len(event):
                event.append('')

            data = {'timestamp' : event[1],
                    'typeDesc'  : event[4],
                    'type' : event[3],
                    'severity' : event[8],
                    'id': event[0],
                    'source' : event[12],
                    'targets' : event[14],
                    'detail' : event[9],
                    'perspective' : event[7],
                    'netFlowSource' : event[15],
                    'userIdentity' : event[16]
                    }
        else:
            # Try to porecess as IDS event
            data = {'timestamp' : event[1],
                    'typeDesc'  : event[12],
                    'type' : 'IDSP',
                    'severity' : event[13],
                    'id': event[0],
                    'source' : event[3],
                    'targets' : event[5],
                    'detail' : event[9],
                    'perspective' : event[11],
                    'netFlowSource' : event[10],
                    'userIdentity' : ''
                    }
        try:
            logging.info('ID {} - timestamp {} - source IP {}'.format(data['id'],data['timestamp'],data['source']))
            block(args, data)
        except IndexError:
            logging.error('Incorrect number of parametres passed by ADS. {}'.format(event))

    logging.info('--- Everything is done ---')

if __name__ == "__main__":
       main()