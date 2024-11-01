#!/bin/bash

# Author: Michal Zakarovsky
# Description: This script is to quarantine IP on Checkpoint R81 (Build 959) Firewalls. Tested on Kemp Flowmon ADS version 11.03.02.
# Version: 2.0
# Date: 19.08.2021

#Default values
default_user="admin"
default_password="admin123"
default_ipaddress="192.168.47.78"
default_target="gw-bfba64"
default_expiration="3600"

function usage {
    cat << EOF >&2
usage: run-script.sh <options>

Optional:
	--user
	--password
	--ipaddress
	--target
	--expiration

EOF
    exit
}

params="$(getopt -o u:p:i:t:e:h -l user:,password:,ipaddress:,target:,expiration:,help --name "run-script.sh" -- "$@")"

eval set -- "$params"
unset params

# Input parameters to replace default values
while true
do
    case $1 in
        -u|--user)
            user=("${2-}")
            shift 2
            ;;
        -p|--password)
            password=("${2-}")
            shift 2
            ;;
        -i|--ipaddress)
            ipaddress=("${2-}")
            shift 2
            ;;
		-t|--target)
            target=("${2-}")
            shift 2
            ;;
		-e|--expiration)
            expiration=("${2-}")
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

# If input parameters are not set, assign default
if [ -z "$user" ]
then
      user="$default_user"
fi

if [ -z "$password" ]
then
      password="$default_password"
fi

if [ -z "$ipaddress" ]
then
      ipaddress="$default_ipaddress"
fi

if [ -z "$target" ]
then
      target="$default_target"
fi

if [ -z "$expiration" ]
then
      expiration="$default_expiration"
fi

loginURL="https://$ipaddress/web_api/login"
logoutURL="https://$ipaddress/web_api/logout"
discardURL="https://$ipaddress/web_api/discard"
runscriptURL="https://$ipaddress/web_api/run-script"

array=() 
while read line
do
	IFS=$'\t'
	array=($line)
	
done < /dev/stdin

MYSID=`/usr/bin/curl -k -X POST "$loginURL" -H "Content-Type: application/json" -d "{\"user\":\"$user\",\"password\":\"$password\",\"session-name\":\"My Fun Session\",\"session-timeout\":\"3600\"}" -s | grep sid | awk -F'"' '{print $4}'`

script_definition="fw sam -s localhost -f All -t $expiration -J src"
script="$script_definition ${array[10]}"

/usr/bin/curl -s -k \
-H "Content-Type: application/json" \
-H "X-chkp-sid: $MYSID" \
-X POST -d '{"script-name":"FW SAM Block","script":"'"$script"'","targets":"'"$target"'"}' \
$runscriptURL 

/usr/bin/curl -k -X POST "$discardURL" -H "Content-Type: application/json" -H "X-chkp-sid: $MYSID" -d "{}" -s
/usr/bin/curl -k -X POST "$logoutURL" -H "Content-Type: application/json" -H "X-chkp-sid: $MYSID" -d "{}" -s