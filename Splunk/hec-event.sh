#!/bin/bash

# Author: Jiri Knapek
# Description: This is example intgeration script for a Splunk HTTP Event Collector (HEC)
# Version: 1.0
# Date: 4/25/2023
# Debug 1 = yes, 0 = no
DEBUG=1
# Management IP/hostname of Splunk server
IP='prd-p-2730i.splunkcloud.com:8088'
API_KEY='8e4266c8-7a27-4e94-8fa8-70f89f1e7be8'
# This is randomly generated GUID for the data channel. If you run multiple instances each script should have it's own.
CHANNEL='c606ba89-6380-4e85-a0d3-33da6f0d9a48'
# Splunk HEC endpoint
HEC="https://$IP/services/collector/raw?channel=$CHANNEL"

function usage {
    cat << EOF >&2
usage: hec-event.sh <options>

Optional:
    --srv       IP / hostname<:port> of Splunk server
	--key		Splunk HEC token
    
EOF
    exit
}   


params="$(getopt -o s:k:h -l srv:,key:,help --name "hec-event.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /tmp/hec-event.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /tmp/hec-event.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -s|--srv)
            IP=("${2-}")
            shift 2
            ;;
        -k|--key)
            API_KEY=("${2-}")
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
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /tmp/hec-event.log 2>&1
}

cat << EOF >&2
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
---------------------------------------
EOF

[ $DEBUG -ne 0 ] && cat >> /tmp/hec-event.log << EOF >&2
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
---------------------------------------
EOF

echo "Stdin read started..." >&2

LINE_NUM=1
array=()
AUTH="Authorization: Splunk $API_KEY"
while read line
do
    IFS=$'\t'
    array=($line)
    first_f=$(date --date="@${array[2]}")
    DATA="{\"source\": \"flowmon-ads\", \"time\":\"$first_f\", \"event\":\"ads_id: ${array[0]}, ${array[3]}, \
description: ${array[4]}, detail: ${array[7]}, Perspective: ${array[5]} \
priority: ${array[6]}, data_feed: ${array[13]}, user_identity: ${array[14]}, source: ${array[10]} \
event_target: ${array[12]}\"}"
    echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}"
    [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}" >> /tmp/hec-event.log 2>&1
    
    LINE_NUM=$((LINE_NUM+1))

    # Send the event to Splunk HEC collector
    if [ $DEBUG -ne 0 ]; then
        /usr/bin/curl -k -X POST -H "Content-Type": "application/json" -H "$AUTH" --data "$DATA" $HEC >> /tmp/hec-event.log 2>&1
    else
        /usr/bin/curl -k -X POST -H "Content-Type": "application/json" -H "$AUTH" --data "$DATA" $HEC
    fi

done < /dev/stdin

echo "---- Everything completed ----"
[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /tmp/hec-event.log