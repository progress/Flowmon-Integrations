#!/bin/bash

# Author: Jiri Knapek
# Description: This script is to quarantine IP or MAC on Fortigate Firewalls and Security Fabric
# Version: 2.1
# Date: 9/16/2020
# Debug 1 = yes, 0 = no
DEBUG=1

[ $DEBUG -ne 0 ] && echo `date` "Starting mitigation script" >> /data/components/apps/log/fg-mitigation.log

# Flowmon API access
USER='admin'
PASS='admin'
# Management IP/hostname of Firewall/ Core device
IP='192.168.47.28'
WEBHOOK='FlowmonADS'
API_KEY='fp8114zdNpjp8Qf8zN4Hdp57dhgjjf'
MAC=1
HTTPS=443

URL="https://$IP:$HTTPS/api/v2/monitor/system/automation-stitch/webhook/$WEBHOOK"

function usage {
    cat << EOF >&2
usage: mitigation_script.sh <options>

Optional:
	--fw        IP / hostname of Fortigate firewall
    --port      HTTPS port on the Fortigate firewall
	--user      Username to be used for Flowmon API authentication
	--pass      Password for the user
	--key	    FortiGate API key
	--mac	    Add this parameter to enable MAC mitigation

EOF
    exit
}



params="$(getopt -o f:P:u:p:k:h:m: -l fw:,port:,key:,pass:,user:,help,mac: --name "mitigation_script.sh" -- "$@")"

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
        -P|--port)
            HTTPS=("${2-}")
            shift 2
            ;;
        -k|--key)
            API_KEY=("${2-}")
            shift 2
            ;;
        -p|--pass)
            PASS=("${2-}")
            shift 2
            ;;
        -u|--user)
            USER=("${2-}")
            shift 2
            ;;
        -m|--mac)
            MAC=1
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
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Got to usage." >> /data/components/apps/log/fg-mitigation.log 2>&1
}

if [ $MAC -ne 0 ];
then
    # authenticate to localhost
    OUTPUT="$(/usr/bin/curl "https://localhost/resources/oauth/token" -k -d 'grant_type=password' -d 'client_id=invea-tech' -d "username=$USER" -d "password=$PASS")"
    TOKEN=""

    echo "${OUTPUT}" > /data/components/apps/log//access_token.json

    if [[ $OUTPUT == *"access_token"* ]]; then
        [ $DEBUG -ne 0 ] && echo `date` "Successfully authenticated to Flowmon Collector!" >> /data/components/apps/log/fg-mitigation.log
        TOKEN="$(cat /data/components/apps/log//access_token.json | jq '.access_token')"
        TOKEN="${TOKEN//\"}"
        TOKEN="Authorization: bearer "$TOKEN
    fi
fi

cat << EOF >&2
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
URL = $URL
MAC = $MAC
TOKEN = $TOKEN
---------------------------------------
EOF

[ $DEBUG -ne 0 ] && cat >> /data/components/apps/log/fg-mitigation.log <<EOF
-----  My params are ------------------
FW = $IP
API KEY = $API_KEY
URL = $URL
MAC = $MAC
TOKEN = $TOKEN
---------------------------------------
EOF

echo "Stdin read started..." >&2

LINE_NUM=1
array=()
while read line
do
    IFS=$'\t'
    array=($line)
    echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}"
    [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}" >> /data/components/apps/log/fg-mitigation.log 2>&1

    # Call a webhook
    if [ $MAC -ne 0 ];
    then
        MAC_ADDR="$(/usr/bin/curl "https://localhost/rest/ads/event/${array[0]}" -G -k -H "$TOKEN"  | jq '.macAddress')"
        if [ $DEBUG -ne 0 ]; then
            echo `date` "Event IP address: ${array[10]}, MAC address $MAC_ADDR" >> /data/components/apps/log/fg-mitigation.log 2>&1
            /usr/bin/curl -o /dev/null -s -w "%{http_code}\n" -k -X POST -H "Authorization: Bearer $API_KEY" --data "{ \"srcip\": \"${array[10]}\", \"mac\": $MAC_ADDR, \"fctuid\": \"A8BA0B12DA694E47BA4ADF24F8358E2F\"}" $URL >> /data/components/apps/log//fg-mitigation.log 2>&1
            echo `date` "CURL result code $?"

        else
            /usr/bin/curl -k -X POST -H "Authorization: Bearer $API_KEY" --data "{ \"srcip\": \"${array[10]}\", \"mac\": $MAC_ADDR, \"fctuid\": \"A8BA0B12DA694E47BA4ADF24F8358E2F\"}" $URL
        fi
    else
        if [ $DEBUG -ne 0 ]; then
            echo `date` "Event IP address: ${array[10]}" >> /data/components/apps/log/fg-mitigation.log 2>&1
            /usr/bin/curl  -o /dev/null -s -w "%{http_code}\n" -k -X POST -H "Authorization: Bearer $API_KEY" --data "{ \"srcip\": \"${array[10]}\",  \"fctuid\": \"A8BA0B12DA694E47BA4ADF24F8358E2F\"}" $URL >> /data/components/apps/log//fg-mitigation.log 2>&1
            echo `date` "CURL result code $?"
        else
            /usr/bin/curl -k -X POST -H "Authorization: Bearer $API_KEY" --data "{ \"srcip\": \"${array[10]}\",  \"fctuid\": \"A8BA0B12DA694E47BA4ADF24F8358E2F\"}" $URL
        fi
    fi

    LINE_NUM=$((LINE_NUM+1))

done < /dev/stdin

echo "---- Everything completed ----"
[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /data/components/apps/log/fg-mitigation.log
