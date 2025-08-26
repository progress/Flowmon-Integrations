#!/bin/bash

# Author: Jiri Knapek
# Description: This script can be used to send ADS events to MS Teams using webhook
# Version: 1.0
# Date: 8/1/2023
# Debug 1 = yes, 0 = no
DEBUG=1
TEST=0
# Incoming webhook URL
WEBHOOK='https://<Your-URL-HERE>'
# hostname / IP of Flowmon Web UI for links in the messages
flowmon='<Your-Flowmon>'

function usage {
    cat << EOF >&2
usage: $(basename $0) <options>

Optional:
    --webhook       MS Teams Webhook
    --flowmon       IP / Hostname of Flowmon Web UI for links
    --test          This will send a test message with static text
    
EOF
    exit
}   


params="$(getopt -o w:f:t:h -l webhook:,flowmon:,test,help --name "teams-webhook.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /data/components/apps/log/teams-webhook.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /data/components/apps/log/teams-webhook.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -w|--webhook)
            #WEBHOOK=("${2-}")
            shift 2
            ;;
        -f|--flowmon)
            flowmon=("${2-}")
            shift 2
            ;;
        -t|--test)
            TEST=1
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
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /data/components/apps/log/teams-webhook.log 2>&1
}

if [ $TEST -gt 0 ]; then
    DATA="{ \
    \"type\": \"message\", \
    \"attachments\": [ \
        { \
            \"contentType\": \"application/vnd.microsoft.card.adaptive\", \
            \"content\": { \
                \"type\": \"AdaptiveCard\", \
                \"body\": [ \
                    { \
                        "type": \"Container\", \
                        \"width\": \"stretch\", \
                        \"items\": [ \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"**8/28/2023 10:13** Flowmon ADS detected a new event\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Event ID [532028](https://demo.flowmon.com/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList|eventDetail%5B%5D*532028) - **SSH attack**(SSHDICT)\", \
                                \"weight\": \"Bolder\", \
                                \"size\": \"Large\", \
                                \"style\": \"heading\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Priority: **Critical**\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Source: **10.10.9.31**, User identity: N/A\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Targets: 10.100.28.40\" \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Attack from a single attacker has been detected. This attack was unsuccessful. Current targets: 1, attempts: 8, upload: 29.09 KiB, maximal upload: 3.66 KiB; total targets: 1, attempts: 33, upload: 90.92 KiB, maximal upload: 3.66 KiB\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Perspective: **Security Issues**, Data feed: **LAN**\", \
                                \"wrap\": true \
                            } \
                        ] \
                    } \
                ], \
                \"\$schema\": \"http://adaptivecards.io/schemas/adaptive-card.json\", \
                \"version\": \"1.0\" \
            } \
        } \
    ] \
}" 
    # Send the event to Teams
    if [ $DEBUG -ne 0 ]; then
        /usr/bin/curl -o - -k -X POST -H "Content-Type":"application/json" --data "$DATA" $WEBHOOK >> /data/components/apps/log/teams-webhook.log 2>&1
    else
        /usr/bin/curl -k -X POST -H "Content-Type":"application/json" --data "$DATA" $WEBHOOK
    fi
    exit 0
fi


[ $DEBUG -ne 0 ] &&  echo `date` "Stdin read started..." >> /data/components/apps/log/teams-webhook.log

# This is where we point the link in the message
ads="https://$flowmon/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList|eventDetail%5B%5D*"

LINE_NUM=1
array=()
while read line
do
    IFS=$'\t'
    array=($line)
    uid="N/A"
    tmp_uid=`awk '{$array[14]=$array[14]};1'`
    if [ -n "$tmp_uid" ]; then
        uid="**${array[14]}**"
    fi
    # we attempt to translate hostname
    source=`host ${array[10]} | cut -d' ' -f 5`
    if [[ ${source} =~ 'NXDOMAIN' ]]; then
        source=${array[10]}
    else
        source="${source} (${array[10]})"
    fi
    target=`host ${array[12]} | cut -d' ' -f 5`
    if [[ ${target} =~ 'NXDOMAIN' ]]; then
        target=${array[12]}
    else
        target="${target} (${array[12]})"
    fi
    data="{ \
    \"type\": \"message\", \
    \"attachments\": [ \
        { \
            \"contentType\": \"application/vnd.microsoft.card.adaptive\", \
            \"content\": { \
                \"type\": \"AdaptiveCard\", \
                \"body\": [ \
                    { \
                        "type": \"Container\", \
                        \"width\": \"stretch\", \
                        \"items\": [ \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"**${array[1]}** Flowmon ADS detected a new event\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"**${array[4]}** (${array[3]})\", \
                                \"weight\": \"Bolder\", \
                                \"size\": \"Large\", \
                                \"style\": \"heading\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Priority: **${array[6]}**, Event ID [${array[0]}]($ads${array[0]})\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Source: **${source}**, User identity: $uid\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Targets: ${target}\" \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"${array[7]}\", \
                                \"wrap\": true \
                            }, \
                            { \
                                \"type\": \"TextBlock\", \
                                \"text\": \"Perspective: **${array[5]}**, Data feed: **${array[13]}**\", \
                                \"wrap\": true \
                            } \
                        ] \
                    } \
                ], \
                \"\$schema\": \"http://adaptivecards.io/schemas/adaptive-card.json\", \
                \"version\": \"1.0\" \
            } \
        } \
    ] \
}" 
    [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}" >> /data/components/apps/log/teams-webhook.log 2>&1
    
    LINE_NUM=$((LINE_NUM+1))

    # Send the event to Teams
    if [ $DEBUG -ne 0 ]; then
        /usr/bin/curl -o - -k -X POST -H "Content-Type":"application/json" --data "$data" $WEBHOOK >> /data/components/apps/log/teams-webhook.log 2>&1
    else
        /usr/bin/curl -k -X POST -H "Content-Type":"application/json" --data "$data" $WEBHOOK
    fi

done < /dev/stdin

[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /data/components/apps/log/teams-webhook.log
