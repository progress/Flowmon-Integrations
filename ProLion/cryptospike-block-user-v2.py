#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script allows Flowmon ADS and IDS to block users on ProLion CryptoSpike.
Compatible with Flowmon ADS 13 event format (tab-separated stdin).

Author: Jirka Knapek <jirka.knapek@progress.com>
Version 2.1

API token authentication:
  Set the CRYPTOSPIKE_API_TOKEN environment variable before running.
  Example:
    export CRYPTOSPIKE_API_TOKEN="xapp-eyJ..."
    echo "<event>" | python3 cryptospike-block-user-v2.py -i 10.100.24.13

  Alternatively pass via --token argument (less secure — visible in process list).

Token resolution order:
  1. --token CLI argument
  2. CRYPTOSPIKE_API_TOKEN environment variable
  3. File at --token-file path (default: /home/flowmon/cryptospike-token)

Recommended setup:
  echo "xapp-eyJ..." > /home/flowmon/cryptospike-token
  chmod 600 /home/flowmon/cryptospike-token
  chown flowmon:flowmon /home/flowmon/cryptospike-token
=========================================================================================

ADS 13 tab-separated event field layout:
  Without extended options (15 fields):
    0:  ID
    1:  event detection time
    2:  first flow timestamp
    3:  event type
    4:  type description
    5:  perspective
    6:  priority
    7:  event detail
    8:  port numbers
    9:  protocol
    10: event source IP
    11: captured source name
    12: event targets
    13: data feed
    14: user identity

  With extended options (17 fields, subtype + MITRE ATT&CK inserted at indices 4-5):
    0:  ID
    1:  event detection time
    2:  first flow timestamp
    3:  event type
    4:  event subtype
    5:  MITRE ATT&CK
    6:  type description
    7:  perspective
    8:  priority
    9:  event detail
    10: port numbers
    11: protocol
    12: event source IP
    13: captured source name
    14: event targets
    15: data feed
    16: user identity

IDS tab-separated event field layout (14 fields):
    0:  ID
    1:  firstSeen
    2:  lastSeen
    3:  srcIp
    4:  srcPort
    5:  dstIp
    6:  dstPort
    7:  protocol
    8:  signatureId
    9:  signatureName
    10: logSourceIp
    11: logSourceInterface
    12: category
    13: severity

Event type detection is based on field count:
  14 fields  → IDS event
  15 fields  → ADS standard
  17+ fields → ADS extended
=========================================================================================
"""

import argparse
import logging
import os
import requests
import sys
import json
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(
    filename='/data/components/apps/log/cryptospike-api.log',
    format=LOGGING_FORMAT,
    level=logging.DEBUG
)

# Field index offsets depend on whether extended options (subtype + MITRE) are present.
# Extended format has 2 extra fields inserted at positions 4 and 5.
FIELD_COUNT_IDS = 14
FIELD_COUNT_EXTENDED = 17
FIELD_COUNT_STANDARD = 15


def detect_event_type(event):
    """Return 'IDS', 'ADS_EXTENDED', or 'ADS_STANDARD' based on field count."""
    n = len(event)
    if n <= FIELD_COUNT_IDS:
        return 'IDS'
    elif n >= FIELD_COUNT_EXTENDED:
        return 'ADS_EXTENDED'
    else:
        return 'ADS_STANDARD'


def get_field_offsets(event):
    """Return (source_ip_idx, targets_idx, data_feed_idx, user_identity_idx) for ADS events."""
    if len(event) >= FIELD_COUNT_EXTENDED:
        return 12, 14, 15, 16
    else:
        return 10, 12, 13, 14


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog='cryptospike-block-user-v2.py',
        description='Block users on ProLion CryptoSpike based on Flowmon ADS and IDS events.'
    )
    parser.add_argument(
        "-i", "--ip",
        action='store', type=str,
        help="IP address/hostname of the CryptoSpike appliance.",
        default='10.100.24.13'
    )
    parser.add_argument(
        "-t", "--token",
        action='store', type=str,
        help=(
            "API token for CryptoSpike (x-auth-token). "
            "Prefer CRYPTOSPIKE_API_TOKEN env variable or a token file instead."
        ),
        default=None
    )
    parser.add_argument(
        "--token-file",
        action='store', type=str,
        help="Path to a file containing the API token (default: /home/flowmon/cryptospike-token).",
        default='/home/flowmon/cryptospike-token'
    )
    return vars(parser.parse_args())


def build_session(token):
    """Create a requests.Session with the API token pre-set on every request."""
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-auth-token": token,
    })
    return session


def find_sid(session, source):
    """Query CryptoSpike file-activity for the past 30 min to resolve a user ID from a source IP.

    Returns the user ID string if exactly one unique user ID is found, False otherwise.
    """
    current = int(datetime.datetime.now().timestamp())
    previous = int((datetime.datetime.now() - datetime.timedelta(minutes=30)).timestamp())
    url = (
        f"https://{IP}/api/v1/audit/dashboard/file-activity/table"
        f"?=&page=0&size=50&start={previous}&end={current}"
    )

    payload = {
        "path": "",
        "users": [],
        "actions": [],
        "fileType": [],
        "extensions": [],
        "clusters": [],
        "servers": [],
        "shares": [],
        "volumes": [],
        "ips": [source],
        "blocked": []
    }

    try:
        response = session.post(url, data=json.dumps(payload))

        if response.status_code != 200:
            logging.error(
                'Cannot retrieve file activity for IP %s: %s - %s',
                source, response.status_code, response.content
            )
            return False

        logging.info('Looking up file activity for IP %s', source)
        items = response.json().get('items', [])

        if not items:
            logging.debug('No file activity found for IP %s', source)
            return False

        user_id = items[0]['id']
        for item in items:
            if item['id'] != user_id:
                logging.info(
                    'Multiple user IDs found for IP %s — ambiguous, no action taken.', source
                )
                return False

        logging.debug('Resolved UID %s for IP %s', user_id, source)
        return user_id

    except requests.exceptions.RequestException as error:
        logging.error('find_sid error: %s', error)
        return False


def search_user(session, user_name):
    """Search CryptoSpike for a Windows user by name and return their user ID."""
    url = (
        f"https://{IP}/api/v1/audit/users"
        f"?page=0&size=20&search={user_name}&blocked=false&orderBy=&sortDescending=false"
    )

    try:
        response = session.get(url)

        if response.status_code != 200:
            logging.error(
                'Cannot search for user %s: %s - %s',
                user_name, response.status_code, response.content
            )
            return False

        items = response.json().get('items', [])
        if items:
            user_id = items[0]['userId']
            logging.debug('Resolved UID %s for username %s', user_id, user_name)
            return user_id

        logging.debug('No UID found for username %s', user_name)
        return False

    except requests.exceptions.RequestException as error:
        logging.error('search_user error: %s', error)
        return False


def block_user(session, user_id, comment):
    """Set userAccessState to BLOCKED for the given user ID with an audit comment."""
    url = f"https://{IP}/api/v1/analyzer/events/users/access"

    payload = {
        "userId": user_id,
        "userIdType": "WINDOWS",
        "userAccessState": "BLOCKED",
        "comment": comment
    }

    try:
        response = session.post(url, data=json.dumps(payload))

        if response.status_code != 200:
            logging.error(
                'Cannot block user %s: %s - %s',
                user_id, response.status_code, response.content
            )
            return False

        logging.info('User %s successfully blocked', user_id)
        return True

    except requests.exceptions.RequestException as error:
        logging.error('block_user error: %s', error)
        return False


def process_ads_event(session, event):
    """Handle an ADS tab-separated event: resolve user ID and block."""
    def safe_get(lst, idx, fallback='n/a'):
        try:
            return lst[idx] or fallback
        except IndexError:
            return fallback

    source_idx, targets_idx, feed_idx, identity_idx = get_field_offsets(event)
    source_ip = safe_get(event, source_idx)

    logging.info('ADS event ID %s — source IP %s', event[0], source_ip)

    comment = (
        f"Flowmon ADS Event ID {safe_get(event, 0)} - {safe_get(event, 3)}\n"
        f"Source: {source_ip}, "
        f"User identity: {safe_get(event, identity_idx)} - "
        f"Targets: {safe_get(event, targets_idx)}\n"
        f"Data feed: {safe_get(event, feed_idx)}"
    )

    user_id = find_sid(session, source_ip)

    if user_id:
        block_user(session, user_id, comment)
    else:
        # Fallback: resolve by user identity name if available
        identity = safe_get(event, identity_idx, fallback='')
        if identity and identity != 'n/a':
            user_id = search_user(session, identity)
            if user_id:
                block_user(session, user_id, comment)


def process_ids_event(session, event):
    """Handle an IDS tab-separated event: resolve user ID from srcIp and block."""
    def safe_get(lst, idx, fallback='n/a'):
        try:
            return lst[idx] or fallback
        except IndexError:
            return fallback

    # IDS field indices
    src_ip = safe_get(event, 3)

    logging.info(
        'IDS event ID %s — src IP %s, signature: %s',
        safe_get(event, 0), src_ip, safe_get(event, 9)
    )

    comment = (
        f"Flowmon IDS Event ID {safe_get(event, 0)}\n"
        f"Signature: [{safe_get(event, 8)}] {safe_get(event, 9)}\n"
        f"Source: {src_ip}:{safe_get(event, 4)} → "
        f"Destination: {safe_get(event, 5)}:{safe_get(event, 6)}\n"
        f"Protocol: {safe_get(event, 7)}, Category: {safe_get(event, 12)}, "
        f"Severity: {safe_get(event, 13)}\n"
        f"Log source: {safe_get(event, 10)} ({safe_get(event, 11)})"
    )

    user_id = find_sid(session, src_ip)
    if user_id:
        block_user(session, user_id, comment)
    else:
        logging.info('IDS event ID %s: no unique user ID resolved for %s', event[0], src_ip)


def main():
    global IP
    logging.info('------- New run -------')

    args = parse_arguments()
    IP = args["ip"]

    # Resolve token: CLI arg → env var → token file.
    token = args.get("token") or os.environ.get("CRYPTOSPIKE_API_TOKEN")
    if not token:
        token_file = args.get("token_file")
        try:
            with open(token_file, 'r') as f:
                token = f.read().strip()
            logging.debug('API token loaded from %s', token_file)
        except FileNotFoundError:
            logging.error('Token file not found: %s', token_file)
        except PermissionError:
            logging.error('Permission denied reading token file: %s', token_file)

    if not token:
        logging.error(
            'No API token provided. Use --token, CRYPTOSPIKE_API_TOKEN, or a token file at %s.',
            args.get("token_file")
        )
        sys.exit(1)

    session = build_session(token)

    for line in sys.stdin:
        event = line.rstrip().split('\t')
        event_type = detect_event_type(event)

        try:
            if event_type == 'IDS':
                process_ids_event(session, event)
            else:
                process_ads_event(session, event)

        except IndexError:
            logging.error('Unexpected event field count (%d fields): %s', len(event), event)

    logging.info('--------- Run complete ---------')


if __name__ == "__main__":
    main()
