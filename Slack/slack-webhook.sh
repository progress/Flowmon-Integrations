#!/bin/bash

# Author: Jiri Knapek
# Description: This script can be used to send ADS events to slack webhook
# Version: 1.0
# Date: 8/2/2023
# Debug 1 = yes, 0 = no
DEBUG=1
TEST=0
# Incoming webhook URL
webhook='https://hooks.slack.com/services/'
# hostname / IP of Flowmon Web UI for links in the messages
flowmon='10.100.24.66'

# This is where we point the link in the message

function usage {
    cat << EOF >&2
usage: $(basename $0) <options>

Optional:
    --webhook       slack Webhook
    --flowmon       IP / Hostname of Flowmon Web UI for links
    --test          This will send a test message with static text
    
EOF
    exit
}   


params="$(getopt -o w:f:t:h -l webhook:,flowmon:,test:,help --name "slack-webhook.sh" -- "$@")"

if [ $? -ne 0 ]
then
    usage
    [ $DEBUG -ne 0 ] && echo `date` "Got to usage." >> /data/components/apps/log/slack-webhook.log
fi

[ $DEBUG -ne 0 ] && echo `date` "Params $params" >> /data/components/apps/log/slack-webhook.log

eval set -- "$params"
unset params

while true
do
    case $1 in
        -w|--webhook)
            webhook=("${2-}")
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
    [ $DEBUG -ne 0 ] &&  echo `date`  "INFO: Too many arguments. Got to usage." >> /data/components/apps/log/slack-webhook.log 2>&1
}

if [ $TEST -gt 0 ]; then
    DATA="{ \"blocks\": [ { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"*8/28/2023 10:13* Flowmon ADS detected a new event\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"*SSH attack* (SSHDICT)\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"Priority: *Critical*, Event ID <https://demo.flowmon.com/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList%7CeventDetail%5B%5D*532028|532028>\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"Source: *10.10.9.31*, User identity: N/A\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"Targets: 10.100.28.40\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"Attack from a single attacker has been detected. This attack was unsuccessful. Current targets: 1, attempts: 8, upload: 29.09 KiB, maximal upload: 3.66 KiB; total targets: 1, attempts: 33, upload: 90.92 KiB, maximal upload: 3.66 KiB\" } }, { \"type\": \"section\", \"text\": { \"type\": \"mrkdwn\", \"text\": \"Perspective: *Security Issues*, Data feed: *LAN*\" } } ] }" 
    # Send the event to slack
    if [ $DEBUG -ne 0 ]; then
        /usr/bin/curl -k -X POST -H "Content-Type":"application/json" --data "$DATA" $webhook >> /data/components/apps/log/slack-webhook.log 2>&1
    else
        /usr/bin/curl -k -X POST -H "Content-Type":"application/json" --data "$DATA" $webhook
    fi
    exit 0
fi


[ $DEBUG -ne 0 ] &&  echo `date` "Stdin read started..." >> /data/components/apps/log/slack-webhook.log

ads="https://$flowmon/adsplug/events/?_adsLink=tab*Tab.Events.SimpleList%7CeventDetail%5B%5D*"

LINE_NUM=1
array=()
while read line
do
    IFS=$'\t'
    array=($line)
    uid="N/A"
    tmp_uid=`awk '{$array[14]=$array[14]};1'`
    if [ -n "$tmp_uid" ]; then
        uid="*${array[14]}*"
    fi
    data="{ \
  \"blocks\": [ \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"*${array[1]}* Flowmon ADS detected a new event\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"*${array[4]}* (${array[3]})\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"Priority: *${array[6]}*, Event ID <$ads${array[0]}|${array[0]}>\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"Source: *${array[10]}*, User identity: $uid\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"Targets: ${array[12]}\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"${array[7]}\" \
      } \
    }, \
    { \
      \"type\": \"section\", \
      \"text\": { \
        \"type\": \"mrkdwn\", \
        \"text\": \"Perspective: *${array[5]}*, Data feed: *${array[13]}*\" \
      } \
    } \
  ] \
}"
    [ $DEBUG -ne 0 ] &&  echo "$LINE_NUM - ID ${array[0]} - type ${array[4]} - source ${array[10]}" >> /data/components/apps/log/slack-webhook.log 2>&1
    
    LINE_NUM=$((LINE_NUM+1))

    # Send the event to slack
    if [ $DEBUG -ne 0 ]; then
        echo $data >> /data/components/apps/log/slack-webhook.log
        /usr/bin/curl -o - -k -X POST -H "Content-Type":"application/json" --data "$data" $webhook >> /data/components/apps/log/slack-webhook.log 2>&1
    else
        /usr/bin/curl -k -X POST -H "Content-Type":"application/json" --data "$data" $webhook
    fi

done < /dev/stdin

[ $DEBUG -ne 0 ] &&  echo `date` "---- Everything completed ----" >> /data/components/apps/log/slack-webhook.log
