#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sqlite3
from sqlite3 import Error
import logging
import json
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# IP of LoadMmaster
IP = '10.100.24.153'
# API key for Loadmaster
API_KEY = 'MDttKNcAx6Eq1achO818ZJNJg3pYqCfNIQiLyiMi9mUz'
# Time to live in hours
TTL = 1800
# How often is this script triggered?
decrese = 24

LOGGING_FORMAT = '%(asctime)s - %(module)s - %(levelname)s : %(message)s'
logging.basicConfig(filename='/data/components/apps/log/lm-timeout.log', format=LOGGING_FORMAT, level=logging.DEBUG)

def parse_arguments():
    parser = argparse.ArgumentParser(prog='lm-timeout.py')
    parser.add_argument("-a", "--add", action='store', type=str, help="Add IP address to the tiemout DB")
    parser.add_argument("-e", "--event", action='store', type=str, help="Event ID for the adding")
    parser.add_argument("-v", "--vs", action='store', type=int, help="Virtual service ID")
    arguments = vars(parser.parse_args())
    return arguments

def create_table(table_sql):
    try:
        c = dbcon.cursor()
        c.execute(table_sql)
    except Error as e:
        logging.error('Cannot create a table: {}'.format(e))
#end def create_table(table_sql)

def db_init():
    sql_create = """CREATE TABLE IF NOT EXISTS data (
                        ip TEXT PRIMARY KEY,
                        event TEXT NOT NULL,
                        vsid integer,
                        ttl integer NOT NULL
                    );"""

    if dbcon is not None:
        create_table(sql_create)
        logging.info('Persistent DB initialized')
    else:
        logging.error('Connection to database is not established')
#end def db_init():

def create_connection():
    try:
        dbcon = sqlite3.connect('/home/flowmon/lm-mitigation/lm-block.db', isolation_level=None)
        logging.debug('SQLite3 version connected: {}'.format(sqlite3.version))
    except Error as e:
        logging.error('Connection to DB failed: {}'.format(e))

    return dbcon
#end def create_connection()

def add_ip(srcip, eid, vsid, ttl):
    entry = (srcip, eid, vsid, ttl)
    sql = 'INSERT INTO data(ip,event,vsid,ttl) VALUES(?,?,?,?);'
    try:
        cur = dbcon.cursor()
        cur.execute(sql,entry)
        logging.debug('Inseted succesffully new IP entry {}'.format(cur.rowcount))
    except sqlite3.Error as e:
        logging.error('Failed to insert IP to DB {}'.format(e))
        return False

    return cur.lastrowid
#def add_ip(srcip, eid, ttl)

def update_ip(srcip, ttl):
    sql = 'UPDATE data SET ttl = ? WHERE ip = ?;'
    entry = (ttl,srcip)
    try:
        cur = dbcon.cursor()
        cur.execute(sql,entry)
        logging.debug('Updated TTL for IP {} '.format(srcip))
    except sqlite3.Error as e:
        logging.error('Failed to update IP record {}'.format(e))
        return False

    return cur.lastrowid
#def update_ip(srcip, ttl)

def delete_ip(srcip):
    sql = 'DELETE FROM data WHERE ip=?;'
    entry = (srcip,)
    try:
        cur = dbcon.cursor()
        cur.execute(sql,entry)
        logging.debug('Deleted DB IP entry {}'.format(srcip))
    except sqlite3.Error as e:
        logging.error('Failed to delete IP from DB {}'.format(e))
        return False

    return cur.lastrowid
#end def delete_ip(srcip)

def get_all_ip():
    sql = 'SELECT * FROM data;'
    try:
        cur = dbcon.cursor()
        cur.execute(sql)
    except sqlite3.Error as e:
        logging.error('Failed to retreive IPs from DB {}'.format(e))
        return False
    
    return cur.fetchall()
#end def get_all_ip()


# Delete IP address from block list
def remove_ip(record):
    url = f"https://{IP}/accessv2"

    if isinstance(record[2], int):
        # VS ID is set so just block at the VS
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(API_KEY),
                    "delvs": "block",
                    "vs": "{}".format(record[2]),
                    "addr": record[0]
                    }
    else:
        # No VS ID so we are blocking global
        payload = {
                    "cmd": "aclcontrol",
                    "apikey": "{}".format(API_KEY),
                    "del": "block",
                    "addr": record[0]
                    }
    print(payload)
    response = requests.post(url, json=payload, verify=False)
    if response.status_code == 200:
        logging.debug('IP address removed from the ACL.')
        delete_ip(record[0])
        return json.loads(response.content)
    else:
        logging.error('Cannot remove IP address HTTP Code {} - {}'.format(response.status_code, response.content))

def main():
    global dbcon
    global IP
    global API_KEY

    args = parse_arguments()

    dbcon = create_connection()
    db_init()

    if isinstance(args['add'], str):
        add_ip(args['add'], args['event'], args['vs'], TTL)
        exit(0)

    logging.info('Starting timeout script')
    for record in get_all_ip():
        # decrease TTL
        if int(record[3]) > decrese:
            update_ip(record[0],(record[3] - decrese))
        # if <= TTL
        else:
            remove_ip(record)
        # delete from table

    logging.info('Everything is done')

if __name__ == "__main__":
       main()