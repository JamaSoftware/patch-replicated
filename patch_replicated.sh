#!/usr/bin/env bash

set -o errexit
set -o pipefail
#set -o xtrace

## This script...
#  1) Enforces correct privileges for successful execution
#  2) Has been tested on Replicated 2.10.0 and up, all the way to 2.42.4
#  3) Only patches Replicated versions 2.10.0 and up
#  4) Respects a proxy configuration to get out to the internet, ie. https://get.jamasoftware.com/docker 
#  5) Safe to run multiple times, meaning it only patches if needed 
#  6) Patching details in order of operation...
#       < 2.10.0 --> exits script
#       = 2.10.0 --> 2.32.4
#       < 2.32.4 --> 2.32.4   Jama Connect released 8.36.x with Replicated 2.32.2
#       < 2.38.6 --> 2.38.6   Jama Connect released 8.42.x with Replicated 2.38.1; Everything beyond is in testing
#       < 2.39.4 --> 2.39.4
#       < 2.40.4 --> 2.40.4
#       < 2.41.1 --> 2.41.1
#       < 2.42.5 --> 2.42.5   I believe this is our target version for the 8.49.x release. Works great from my standpoint

## What the script does not do...
#  1) Consider airgap installations, yet...

## Ensure you are the root user or have sudo privileges
if [[ $EUID > 0 ]]; then
    echo "Please run as root/sudo"
    exit 1
fi

## Ensure Replicated is installed
if [ ! -e /usr/local/bin/replicated ]; then
        echo "Replicated not found: /usr/local/bin/replicated"
        exit 0
fi

## Get the version of Replicated currently installed and exit if patching is uneeded
currentReplicatedVer="$(/usr/local/bin/replicated --version | awk '{print $3}')"
if [[ "${currentReplicatedVer}" =~ ^(2.42.4|2.41.1|2.40.4|2.39.4|2.38.6|2.37.2|2.32.4)$ ]]; then
	echo "No update needed. You're running Replicated ${currentReplicatedVer}"
        exit 0
else
	## Set some variables to be used with the install/upgrade commands below
	hostIp="$(/usr/local/bin/replicatedctl params export | grep LocalAddress | awk -F '\"' '{print $4}')"
	proxyEnabled="$(/usr/local/bin/replicatedctl params export | grep 'HttpProxyDisabled' | awk '{print $NF}' | sed 's/,.*//')"
    tlsType=$(/usr/local/bin/replicatedctl params export | grep -i 'TLSBootstrapType' | awk -F '"' '{print $4}')
    tlsHostname=$(/usr/local/bin/replicatedctl params export | grep -i 'TLSBootstrapHostname' | awk -F '"' '{print $4}')
    tlsKey=$(/usr/local/bin/replicatedctl params export | grep -i 'TLSBootstrapKey' | awk -F '"' '{print $4}')
    tlsCert=$(/usr/local/bin/replicatedctl params export | grep -i 'TLSBootstrapCert' | awk -F '"' '{print $4}')
    airgapEnabled="$(/usr/local/bin/replicatedctl params export | grep 'Airgap":' | awk '{print $NF}' | sed 's/,.*//')"
    if [[ ${airgapEnabled} == "true" ]]; then
        airgapPath="$(/usr/local/bin/replicatedctl params export | grep 'AirgapPackagePath":' | awk -F '"' '{print $4}')"
    fi
fi

## If a patch is needed, identify the major version and set the new version to upgrade Replicated to
if [[ ${currentReplicatedVer} < "2.10.0" ]]; then
	echo "No update needed. You're running Replicated ${currentReplicatedVer}"
	exit 0
elif [[ ${currentReplicatedVer} == "2.10.0" ]]; then
	newReplicatedVer='2.32.4'
elif [[ ${currentReplicatedVer} < "2.32.4" ]]; then
	newReplicatedVer='2.32.4'
elif [[ ${currentReplicatedVer} < "2.38.6" ]]; then
	newReplicatedVer='2.38.6'
elif [[ ${currentReplicatedVer} < "2.41.1" ]]; then
	newReplicatedVer='2.41.1'
elif [[ ${currentReplicatedVer} < "2.42.5" ]]; then
	newReplicatedVer='2.42.5'
fi

## Execute the command to upgrade Replicated to a patched version, hotfix, for the major release already installed
## AIRGAP installation method:
if [[ ${airgapEnabled} == "true" ]]; then
    replicatedDownloadUrl="https://s3.amazonaws.com/replicated-airgap-work/stable/replicated-${newReplicatedVer}%2B${newReplicatedVer}%2B${newReplicatedVer}.tar.gz"
    replicatedFileName="$(echo ${replicatedDownloadUrl} | awk -F '/' '{print $NF}' | sed 's/\%2B/\+/g')"
    if [ ! -f ${airgapPath}/${replicatedFileName} ]; then
        which wget > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Install the wget package then try again..."
            exit 0
        fi
        wget --continue --show-progress "${replicatedDownloadUrl}" -P ${airgapPath}
        if [ $? -ne 0 ]; then
            echo -e "ERROR: Could not download ${replicatedDownloadUrl}\n"
            echo "Your deployment method is "Airgap" and we could not automatically download it for you"
            echo "Please download the following package and upgrade Replicated manually"
            echo "    Download ${replicatedDownloadUrl} to your server, under ${airgapPath}"
            echo "    Extract it to ${airgapPath}"
            echo "        tar -xzvf ${replicatedFileName} -C ${airgapPath} --overwrite"
            echo "    Upgrade Replicated, the Admin Console"
            echo "        cd ${airgapPath}"
            echo "        cat install.sh | sudo bash -s airgap private-address=${hostIp} public-address=${hostIp}"
            echo -e "Then replace your TLS certificate and key!\n"
            ## There's a defect with Replicated not showing the TLSBootstrap info in airgap systems
            exit 0
        fi
    else
        ## Execute the upgrade
        tar -xzvf ${airgapPath}/${replicatedFileName} -C ${airgapPath} --overwrite
        cd ${airgapPath}
        cat install.sh | bash -s airgap private-address=${hostIp} public-address=${hostIp}
        newReplicatedVer="$(/usr/local/bin/replicatedctl --version | awk '{print $3}')"
    	echo "SUCCESS: Replicated ${currentReplicatedVer} has been successfully patched to ${newReplicatedVer}"
        echo -e "\tReplace your TLS certificate and key!\n"
        ## There's a defect with Replicated not showing the TLSBootstrap info in airgap systems
    fi
else
    ## INTERNET installation method
    if [[ ${proxyEnabled} == "false" ]]; then
    	proxyAddress="$(/usr/local/bin/replicatedctl params export | grep 'HttpProxy":' | awk -F '"' '{print $4}')"
    	echo "${currentReplicatedVer} being upgraded to ${newReplicatedVer}"
    	curl -sSL "https://get.jamasoftware.com/docker?replicated_tag=${newReplicatedVer}" \
    	  | bash -s local-address=${hostIp} public-address=${hostIp} http-proxy="${proxyAddress}" no-docker
    	if [ $? -eq 0 ]; then
    		newReplicatedVer="$(/usr/local/bin/replicatedctl --version | awk '{print $3}')"
    		echo -e "SUCCESS: Replicated ${currentReplicatedVer} has been successfully patched to ${newReplicatedVer}\n"
            echo "Replace your TLS certificate and key:"
            echo -e "\tHostname:${tlsHostname}"
            echo -e "\tTLS Key :${tlsKey}"
            echo -e "\tTLS Cert: ${tlsCert}\n" 
    	fi
    else
    	echo "Replicated ${currentReplicatedVer} is being upgraded to ${newReplicatedVer}"
    	curl -sSL "https://get.jamasoftware.com/docker?replicated_tag=${newReplicatedVer}" \
    	  | bash -s local-address=${hostIp} public-address=${hostIp} no-proxy=1 no-docker
    	if [ $? -eq 0 ]; then
    		newReplicatedVer="$(/usr/local/bin/replicatedctl --version | awk '{print $3}')"
    		echo -e "SUCCESS: Replicated ${currentReplicatedVer} has been successfully patched to ${newReplicatedVer}\n"
            echo "Replace your TLS certificate and key:"
            echo -e "\tHostname:${tlsHostname}"
            echo -e "\tTLS Key :${tlsKey}"
            echo -e "\tTLS Cert: ${tlsCert}\n" 
    	fi
    fi
fi

