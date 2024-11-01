#!/bin/bash

# Author: Jiri Knapek
# Description: This script can be used to trigger backup on Superna Eyeglass
# Version: 1.0
# Date: 8/29/2023
# Debug 1 = yes, 0 = no
DEBUG=1
# hostname / IP of Flowmon Web UI for links in the messages
ip='10.100.24.66'

# This is where we point the link in the message

function usage {
    cat << EOF >&2
usage: $(basename $0) <options>

Optional:
    --ip       IP / Hostname of Superna Eyeglass API
    --key      API key from Superna
    
EOF
    exit
}   


params="$(getopt -o i:k:h -l ip:,key:,help --name "superna-rd.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /tmp/superna-rd.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /tmp/superna-rd.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -i|--ip)
            ip=("${2-}")
            shift 2
            ;;
        -k|--key)
            key=("${2-}")
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

# API URL
url="https://$ip/sera/v2/ransomware/criticalpaths"

# we dont support any other args
[ $# -gt 0 ] && {
    usage
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /tmp/superna-rd.log 2>&1
}

[ $DEBUG -ne 0 ] &&  echo `date` "Sending notification to API..." >> /tmp/superna-rd.log

# Send request to Superna Eyeglass Ransomware defender
if [ $DEBUG -ne 0 ]; then
  /usr/bin/curl -o - -k -X POST -H "Content-Type":"application/json" --header 'Accept: application/json' --header "api_key: $key"--data "{}" $url >> /tmp/superna-rd.log 2>&1
else
  /usr/bin/curl -k -X POST -H "Content-Type":"application/json"--header 'Accept: application/json' --header "api_key: $key"--data "{}" $url 
fi

[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /tmp/superna-rd.log
