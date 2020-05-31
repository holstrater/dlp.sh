#!/bin/bash

#Validate command options and create usage instructions

usage=$(printf "Usage:\n\
sudo ./dlp.sh [options] \"&\"&\n\n\
Options:\n\
-k      Add additional keywords to the list of phrases that are monitored. Separated by commas.\n\
        Example: sudo ./dlp.sh -k valuablekeyword,keyphrase \"&\"&\n\n\
-i	Set internal IPv4 address.\n\
	Example: sudo ./dlp.sh -i 192.168.56.88 \"&\"&\n\n\
-m	Set MAC address.\n\
	Example: sudo ./dlp.sh -m 00:10:fa:6e:38:4a \"&\"&\n\n\
-e	Set system administrator's email address.\n\
	Example: sudo ./dlp.sh -e email@domain.com \"&\"&\n\n\
-h	Show usage instructions.\n\
	Example: sudo ./dlp.sh -h \"&\"&\n\n")

if [[ "${!#}" != "&" ]]
then
    echo "$usage"
    exit 1
elif [[ "$EUID" -ne 0 ]]
then
    printf "Please rerun the program as root, for example by typing sudo before the command.\n\
For more usage instructions, add the -h option when running the program.\n"
    exit 1
fi

while getopts ":i:m:k:e:h" o
do
    case "$o" in
        i)
            u_ip4_internal=$OPTARG
            ;;
        m)
            u_mac=$OPTARG
            ;;
        k)
            u_key=$OPTARG
            ;;
        e)
            u_email=$OPTARG
            ;;
        h)
            echo "$usage"
            exit 1
    esac
done
shift $((OPTIND-1))

#Check for (steady) internet connection and access to essential commands

printf "\nWelcome to DLP.sh, a network monitor that identifies harmful activity.\n\
Monitoring will remain active in the background but relies on the Terminal app.\n\
Minimizing it or executing other commands is OK, but please do not close the Terminal app.\n\n"

echo "Checking for internet connection... "

if [[ ! $(ping -c 5 8.8.8.8) ]]
then
    printf "No (stable) connection to the internet can be made. Please run this program again later.\n"
    exit 1
elif [[ ! $(which tcpdump) ]]
then
    printf "The tcpdump command could not be located on your device. Either install it or add the existing installation\n\
to your path. If you're unsure how to do this, consult your system administrator.\n"
    exit 1
elif [[ ! $(which mail) ]]
then
    printf "The mail command could not be located on your device. Either install it or add the existing installation\n\
to your path. If you're unsure how to do this, consult your system administrator.\n"
      exit 1
elif [[ ! $(which uuencode) ]]
then
    printf "The uuencode command could not be located on your device. Either install it or add the existing installation\n\
to your path. If you're unsure how to do this, consult your system administrator.\n"
    exit 1
else
    printf "Done.\n"
fi

#Create identifier variables

username="$SUDO_USER"

ip4_internal=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}')
if [[ $(echo "$ip4_internal" | grep -o "\." | grep -c "\.") != 3 ]]
then
		ip4_internal="$u_ip4_internal"
    if [[ $(echo "$ip4_internal" | grep -o "\." | grep -c "\.") != 3 ]]
    then
        printf "A single active internal IPv4 address could not be determined.\n\
Please rerun the program by adding the -i option, specifying a valid internal IPv4 address.\n\
For more usage instructions, add the -h option when running the program.\n"
        exit 1
    fi
fi

if [[ $(which ifconfig) ]]
then
    interface=$(ifconfig | grep -B4 "$ip4_internal" | awk -F':' 'NR==1{print $1}')
elif [[ $(which ip) ]]
then
    interface=$(ip addr show | grep -B2 136.144.226.39 | awk -F':' 'NR==1{print $2}')
fi

mac=$(ifconfig | grep -C2 $ip4_internal | grep "ether " | awk '{print $2}')
if [[ $(echo "$mac" | grep -o "\:" | grep -c "\:") != 5 ]]
then
    mac="$u_mac"
    if [[ $(echo "$mac" | grep -o "\:" | grep -c "\:") != 5 ]]
    then
        printf "A single active MAC address could not be determined.\n\
Please rerun the program by adding the -m option, specifying a valid MAC address.\n\
For more usage instructions, add the -h option when running the program.\n"
        exit 1
    fi
fi

#Create system administrators email variable

if [[ ! "$u_email" == *@*.* ]]
then
    printf "The email address entered for the system administrator could not be validated.\n\
Please rerun the program by adding the -e option, specifying a valid email address used by your system administrator.\n\
For more usage instructions, add the -h option when running the program.\n"
    exit 1
fi

#Create array for sensitive keywords and check for custom keywords added by user

keywords=("password")
keywords+=("passwd")
keywords+=("pass")
keywords+=("credential")
keywords+=("credentials")
keywords+=("secret")

OLDIFS=$IFS

if [[ ! -z "$u_key" ]]
then
    IFS=','
    read -r -a u_key_array <<< "$u_key"
    IFS=$OLDIFS
    for i in "${u_key_array[@]}"
    do
	       keywords+=("$i")
    done
fi

mkdir /tmp/dlp

#Main loop: monitor, analyze and email out alerts

while [[ 1 == 1 ]]
do
    tcpdump -i "$interface" -A -c 500 -w /tmp/dlp/savedcaps.pcap >/dev/null 2>&1
    IFS="|"
    match=$(grep -a -E "${keywords[*]}" /tmp/dlp/savedcaps.pcap)
    IFS=$OLDIFS
    if [[ ! -z "$match" ]]
    then
        mailbody=$(printf "This is an automatically generated alert regarding highly suspicious network activity from user \"$username\".\n\
A small log file containing the activity has been attached to this email. Please investigate immediately.\n\n\
Username:                            $username\n\
Internal IPv4 address:            $ip4_internal\n\
MAC address:                       $mac\n\n\
Keywords detected:\n\n\
$match")
        (echo "$mailbody"; uuencode /tmp/dlp/savedcaps.pcap /tmp/dlp/savedcaps.pcap) | mail \
        -s "ALERT: suspicious network activity detected from user" $u_email
        sleep 1
    fi
done
