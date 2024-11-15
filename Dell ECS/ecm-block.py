#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
"""
This script is to help with blocking of bad actors on ECS Connection Manager using blocklists

=========================================================================================
"""

import argparse
import logging
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='./ecm-api.log', format=LOGGING_FORMAT, level=logging.DEBUG)


def parse_arguments():
    parser = argparse.ArgumentParser(prog='ecm-block.py')
    parser.add_argument("-k", "--key", action='store', type=str, help="REST API key to use for authentication", required=True)
    parser.add_argument("-i", "--ip", action='store', type=str, help="IP address/hostname of the Connection Manager", required=True)
    parser.add_argument("-v", "--vs", action='store', type=int, help="Virtual service ID")
    arguments = vars(parser.parse_args())
    return arguments

def block(args, event):
    url = f"https://{args['ip']}/accessv2"

    if isinstance(args['vs'], int):
        # VS ID is set so just block at the VS
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(args['key']),
                    "addvs": "block",
                    "vs": "{}".format(args['vs']),
                    "addr": event[10],
                    "comment": "ADS ID {} - {}".format(event[0], event[3])
                    }
    else:
        # No VS ID so we are blocking global
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(args['key']),
                    "add": "block",
                    "addr": event[10],
                    "comment": "ADS ID {} - {}".format(event[0], event[3])
                    }
    response = requests.post(url, json=payload, verify=False)

    if response.status_code != 200:
        logging.error('Cannot talk to API {} : {} - {}'.format(args['ip'], response.status_code, response.content))
        return False
    else:
        data = response.json()
        logging.debug(f"Received response: {data}")

def main():
    logging.info('------- New run -------')
    args = parse_arguments()

    if isinstance(args['vs'], int):
        print("yes")
    else:
        print("no")
    # This part is taking care of looping through the stdin until EOF (Ctrl+D)
    for line in sys.stdin:
        event = line.rstrip().split('\t')
        try:
            logging.info('ID {} - timestamp {} - source IP {}'.format(event[0],event[2],event[10]))
            block(args, event)
        except IndexError:
            logging.error('Incorrect number of parametres passed by ADS. {}'.format(event))

    logging.info('--- Everything is done ---')

if __name__ == "__main__":
       main()