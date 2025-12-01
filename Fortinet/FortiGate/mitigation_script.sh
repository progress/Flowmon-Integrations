#!/bin/bash

# Author: Jiri Knapek
# Description: This script is to quarantine IP on Fortigate Firewalls for FortiOS before 6.4.
# Version: 1.4
# Date: 9/16/2020
# Debug 1 = yes, 0 = no
DEBUG=1

[ $DEBUG -ne 0 ] && echo `date` "Starting mitigation script" >> /data/components/apps/log/fg-mitigation.log

# Management IP/hostname of Firewall/ Core device
IP='192.168.47.28'
API_KEY='fp8114zdNpjp8Qf8zN4Hdp57dhgjjf'
# Default timeout for action is
# value in seconds or never
TIMEOUT='300'

# FortiGate API URL
BAN="https://$IP/api/v2/monitor/user/banned/add_users?access_token=$API_KEY"

function usage {
    cat << EOF >&2
usage: mitigation_script.sh <options>

Optional:
    --fw        IP / hostname of Fortigate firewall
	--timeout	Timeout in seconds
	--key		FortiGate API key
    
EOF
    exit
}      

params="$(getopt -o f:t:k:h -l fw:,timeout:,key:,help --name "mitigation_script.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /data/components/apps/log/fg-mitigation.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /data/components/apps/log/fg-mitigation.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -f|--fw)
            IP=("${2-}")
            shift 2
            ;;
        -k|--key)
            API_KEY=("${2-}")
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT=("${2-}")
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            break
            ;;
        *)
            usage
            ;;
    esac
done

# we dont support any other args
[ $# -gt 0 ] && {
    usage
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /data/components/apps/log/fg-mitigation.log 2>&1
}

cat << EOF >&2
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
TIMEOUT = $TIMEOUT
TOKEN = $TOKEN
---------------------------------------
EOF

[ $DEBUG -ne 0 ] && cat >> /data/components/apps/log/fg-mitigation.log << EOF >&2
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
TIMEOUT = $TIMEOUT
TOKEN = $TOKEN
---------------------------------------
EOF

echo "Stdin read started..." >&2

LINE_NUM=1
array=()
while read line
do
    # Check the number of fields
    field_count=$(echo "$line" | awk -F'\t' '{print NF}')
    if [ "$field_count" -eq 16 ]; then
        [ $DEBUG -ne 0 ] &&  echo `date` "Processing ADS event..." >> /data/components/apps/log/fg-mitigation.log 
        echo "Processing ADS event..."
        IFS=$'\t'
        array=($line)
        echo "$LINE_NUM - ID ${array[0]} - type ${array[3]} - source ${array[12]}"
        [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[3]} - source ${array[12]}" >> /data/components/apps/log/fg-mitigation.log 2>&1
        
        LINE_NUM=$((LINE_NUM+1))

        # BAN the source IP of the event
        if [ $DEBUG -ne 0 ]; then
            /usr/bin/curl -k -X POST -H "Content-Type": "application/json" --data "{ \"ip_addresses\": [\"${array[12]}\"], \"expiry\": $TIMEOUT}" $BAN >> /data/components/apps/log/fg-mitigation.log 2>&1
        else
            /usr/bin/curl -k -X POST -H "Content-Type": "application/json" --data "{ \"ip_addresses\": [\"${array[12]}\"], \"expiry\": $TIMEOUT}" $BAN
        fi
    else
        [ $DEBUG -ne 0 ] &&  echo `date` "Processing IDS event..." >> /data/components/apps/log/fg-mitigation.log
        echo "Processing IDS event..."
        IFS=$'\t'
        array=($line)
        echo "$LINE_NUM - ID ${array[0]} - type ${array[9]} - source ${array[3]}"
        [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[9]} - source ${array[3]}" >> /data/components/apps/log/fg-mitigation.log 2>&1
        
        LINE_NUM=$((LINE_NUM+1))

        # BAN the source IP of the event
        if [ $DEBUG -ne 0 ]; then
            /usr/bin/curl -k -X POST -H "Content-Type": "application/json" --data "{ \"ip_addresses\": [\"${array[3]}\"], \"expiry\": $TIMEOUT}" $BAN >> /data/components/apps/log/fg-mitigation.log 2>&1
        else
            /usr/bin/curl -k -X POST -H "Content-Type": "application/json" --data "{ \"ip_addresses\": [\"${array[3]}\"], \"expiry\": $TIMEOUT}" $BAN
        fi
    fi

done < /dev/stdin

echo "---- Everything completed ----"
[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /data/components/apps/log/fg-mitigation.log