#!/bin/bash

# Author: Jiri Knapek
# Description: This is example intgeration script for a ServiceNow which would create an incident by REST API
# Version: 1.0
# Date: 4/25/2023
# Debug 1 = yes, 0 = no
DEBUG=1
# IP/hostname of SericeNow server
IP='dev121928.service-now.com'
API_USER='admin'
API_PASS='K4/t1FbuM$eL'
# ServiceNow ednpoint
SNI="https://$IP/api/now/table/incident"

function usage {
    cat << EOF >&2
usage: sn-incident.sh <options>

Optional:
    --srv       IP / hostname of ServiceNow server
    --user      Username to be used for authentication
	--pass		Password for the user from the above
    
EOF
    exit
}   


params="$(getopt -o s:u:p:h -l srv:,user:,pass:,help --name "sn-incident.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /data/components/apps/log/sn-incident.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /data/components/apps/log/sn-incident.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -s|--srv)
            IP=("${2-}")
            shift 2
            ;;
        -u|--user)
            API_USER=("${2-}")
            shift 2
            ;;
        -p|--pass)
            API_PASS=("${2-}")
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
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /data/components/apps/log/sn-incident.log 2>&1
}

cat << EOF >&2
-----  My params are ------------------
Instance = $IP
User = $API_USER
---------------------------------------
EOF

[ $DEBUG -ne 0 ] && cat >> /data/components/apps/log/sn-incident.log << EOF >&2
-----  My params are ------------------
Instance = $IP
User = $API_USER
---------------------------------------
EOF

echo "Stdin read started..." >&2

LINE_NUM=1
array=()

#  0  ID
#  1  event detection time
#  2  timestamp of the first flow
#  3  event type
#  4  type description
#  5    perspective
#  6    priority
#  7    event detail
#  8  port numbers
#  9   protocol
# 10  event source
# 11  captured source nam
# 12  event targets
# 13  data feed
# 14  user identity

while read line
do
    IFS=$'\t'
    array=($line)
    first_f=$(date --date="@${array[2]}")
    DATA="{\"short_description\":\"ADS - ${array[0]} - ${array[10]} - ${array[3]}\", \
\"category\":\"Network\", \
\"description\":\"${array[4]} Detail: ${array[7]} First Flow: $first_f Perspective: ${array[5]} \
Priority: ${array[6]} Data Feed: ${array[13]} User Identity: ${array[14]} Event source: ${array[10]} \
Event target: ${array[12]}\"}"

    echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}"
    [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}" >> /data/components/apps/log/sn-incident.log 2>&1
    
    LINE_NUM=$((LINE_NUM+1))

    # Send the event to splunk HEC collector
    if [ $DEBUG -ne 0 ]; then
        /usr/bin/curl "$SNI" \
--request POST \
--header "Accept:application/json" \
--header "Content-Type:application/json" \
--data "$DATA" \
--user "$API_USER":"$API_PASS" >> /data/components/apps/log/sn-incident.log 2>&1
    else
        /usr/bin/curl "$SNI" \
--request POST \
--header "Accept:application/json" \
--header "Content-Type:application/json" \
--data "$DATA" \
--user "$API_USER":"$API_PASS"
    fi

done < /dev/stdin

echo "---- Everything completed ----"
[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /data/components/apps/log/sn-incident.log


