#!/bin/bash
#------------------------------
# Script to check and fix SSL trust achors
#
# Author: Vincent Santa Maria [vsantamaria@vmware.com]
# Version: 2.1
#------------------------------

function setOptionColorize() {
   RED=$(tput setaf 1)
   GREEN=$(tput setaf 2)
   YELLOW=$(tput setaf 3)
   CYAN=$(tput setaf 6)
   NORMAL=$(tput sgr0)
}

function unknownOption() {
   echo "Unknown option '$2'. Please see '$1 --help' for usage and available options"
}

CURRENT_SERVICE_ID=''
SHOW_SERVICE_IDS=0
SHOW_ENDPOINTS=0
SHOW_DUPLICATE_ENDPOINTS=0
LIVE_CHECK=0
VIEW_MACHINE_SSL=0
DEBUG=0
FIX=0
TP_ALGORITHM="sha1"
TP_REGEX_ITER="19"
CERT_TEXT=0
CERT_COUNT=1
RED=''
GREEN=''
YELLOW=''
CYAN=''
NORMAL=''
LSTOOL_FILE='lstool.txt'

if [[ ${LIVE_CHECK} -gt 0 ]]; then
   VC_VERSION=$(grep 'CLOUDVM_VERSION:' /etc/vmware/.buildInfo | awk -F':' '{print $NF}' | awk -F'.' '{print $1}')
else
   VC_VERSION=$(grep 'CLOUDVM_VERSION:' ../etc/vmware/.buildInfo | awk -F':' '{print $NF}' | awk -F'.' '{print $1}')
fi

if [[ ${VC_VERSION} -eq 7 ]]; then
   LS_PORT='7090'
   LSTOOL_SCRIPT='/usr/lib/vmware-lookupsvc/tools/lstool.py'
   LSUPDATE_SCRIPT='/usr/lib/vmware-lookupsvc/tools/ls_update_certs.py'
else
   LS_PORT='7080'
   LSTOOL_SCRIPT='/usr/lib/vmidentity/tools/scripts/lstool.py'
   LSUPDATE_SCRIPT='/usr/lib/vmidentity/tools/scripts/ls_update_certs.py'
fi
   

if [ -f /usr/bin/ldapsearch ]; then
   LDAPSEARCH='/usr/bin/ldapsearch'
else
   LDAPSEARCH='/opt/likewise/bin/ldapsearch'
fi

if [ "$#" -ge 1 ]; then
   for arg in "$@"; do
      case ${arg} in
         -h|--help)
            echo "SSL Trust Anchor Verification and Remediation Script"
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "   -s | --show-service-ids   Shows the Service IDs that are using a particular SSL certificate."
            echo "   -e | --show-endpoints     Shows the Endpoing URIs that are using a particular SSL certificate."
            echo "   -c | --colorize           Colorizes text for quick identification of Subject field, SHA1/SHA256 Fingerprint, or"
            echo "                             expired certificates. Do not use if passing output to a paginator or file."
            echo "   -l | --live-check         Used when running the script on a live system, which will automatically dump the"
            echo "                             Lookup Service registrations to /tmp. Must be used with the fix (-f|--fix) option."
            echo "   -m | --machine-ssl        Will display information on the current Machine SSL ceritifcate. Cannot be run on"
            echo "                             a support bundle from an external Platform Services Controller."
            echo "   -t | --cert-text          Will provide full output of each certificate similar to 'openssl x509 -text'"
            echo "   -f | --fix                Will prompt for SSO credentials, thumbprint of a trust anchor cert to update, and the IP/FQDN"
            echo "                             of a node to update."
            echo "   -d | --debug              Will include the raw certificate hash to see if there are any extra characters"
            echo "                             (sometimes the lstool.py script has connection issues and STDERR gets randomly"
            echo "                             inserted in the output)."
            echo "   -h | --help               Prints this help menu."
            echo "   -2 | --sha256             Outputs the SHA256 thumbprint of the certificates instead of the SHA1 thumbprint"
            echo $'\n'"Parses the output of the following command from the Platform Services Controller:"
            echo "${LSTOOL_SCRIPT} list --url http://localhost:${LS_PORT}/lookupservice/sdk 2>/dev/null"
            echo $'\n'"Can be run from the 'commands/' directory of a support bundle, or live on a PSC node."
            exit
            ;;

         --show-service-ids)
            SHOW_SERVICE_IDS=1
            ;;

         --show-endpoints)
            SHOW_ENDPOINTS=1
            ;;
         --colorize)
            setOptionColorize
            ;;
         --live-check)
            LIVE_CHECK=1
            ;;
         --machine-ssl)
            VIEW_MACHINE_SSL=1
            ;;
         --debug)
            DEBUG=1
            ;;
         --cert-text)
            CERT_TEXT=1
            ;;
         --fix)
            FIX=1
            ;;
         --sha256)
            TP_ALGORITHM="sha256"
            TP_REGEX_ITER="31"
            ;;
         -[seclmfdt2]*)
            OPT=$(echo "z${arg}" | sed 's/z-//')
            for (( i=0; i<${#OPT}; i++ )); do
               case ${OPT:$i:1} in
                  s)
                     SHOW_SERVICE_IDS=1
                     ;;
                  e)
                     SHOW_ENDPOINTS=1
                     ;;
                  c)
                     setOptionColorize
                     ;;
                  d)
                     DEBUG=1
                     ;;
                  l)
                     LIVE_CHECK=1
                     ;;
                  m)
                     VIEW_MACHINE_SSL=1
                     ;;
                  t)
                     CERT_TEXT=1
                     ;;              
                  f)
                     FIX=1
                     ;;
                  2)
                     TP_ALGORITHM="sha256"
                     TP_REGEX_ITER="31"
                     ;;
                  *)
                     unknownOption $0 '-${OPT:$i:1}'
                     exit
                     ;;
               esac
            done
            ;;
         *)
            unknownOption $0 ${arg}
            exit
            ;;
      esac
   done
fi

if [[ ${LIVE_CHECK} -eq 0 ]]; then
   if [ ! -f ${LSTOOL_FILE} ]; then
      if [ ! -f "python.exe_VMWARE_CIS_HOMEVMwareIdentityServiceslstoolscriptslstoolpy-list---url-httplocalhost7080lo[...].txt" ]; then
         echo "${YELLOW}No output from 'lstool.py list' found in this bundle."
      else
         LSTOOL_FILE='python.exe_VMWARE_CIS_HOMEVMwareIdentityServiceslstoolscriptslstoolpy-list---url-httplocalhost7080lo[...].txt'
      fi
   fi
   if [ -f ../etc/vmware/deployment.node.type ]; then
      NODE_TYPE=$(cat ../etc/vmware/deployment.node.type)
   elif [ -f ../ProgramData/VMware/vCenterServer/cfg/deployment.node.type ]; then
      NODE_TYPE=$(cat ../ProgramData/VMware/vCenterServer/cfg/deployment.node.type)
   fi
else
   NODE_TYPE=$(cat /etc/vmware/deployment.node.type)
   if [ ${NODE_TYPE} == 'management' ]; then
      echo "${YELLOW}Operation not supported on a Management Node. Please run this live on a PSC node. Exiting...${NORMAL}"
      exit
   fi
   
   if [ ! -f ${LSTOOL_FILE} ]; then LSTOOL_FILE='/tmp/lstool.txt'; fi
      
   echo "${YELLOW}No 'lstool.txt' file found in this directory. Dumping service registrations to ${LSTOOL_FILE}...${NORMAL}"
   ${LSTOOL_SCRIPT} list --url http://localhost:${LS_PORT}/lookupservice/sdk 2>/tmp/lstool_stderr > ${LSTOOL_FILE}      
fi

DATA=$(cat ${LSTOOL_FILE} | grep -vE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | grep -E 'Service ID:|URL:|SSL trust:|^[0-9A-Za-z/\+]' | tr -d ' ' | tr -d '\n' | tr -d '\t' | tr -d '\r\n' | sed -e 's/ServiceID:/\nServiceID:/g' -e 's/URL:/\nURL:/g' -e 's/SSLtrust:/\nSSLtrust:/g')
TRUST_ANCHORS=$(echo "${DATA}" | grep 'SSLtrust' | sed -e 's/SSLtrust://g' | sort | uniq)

for RAW_HASH in ${TRUST_ANCHORS}; do
   echo "${CYAN}-----Endpoint Certificate ${CERT_COUNT}-----${NORMAL}"

   if [[ ${RAW_HASH} =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
      echo "${RED}Malformed hash detected${NORMAL}"
      BAD=$(echo "${RAW_HASH}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}(.)+')
      HASH="$(echo "${RAW_HASH}" | sed -e 's/${BAD}//')"
      CHARS=${#HASH}
      MOD=$((${CHARS} % 4))
      case ${MOD} in
         3)
            HASH="${HASH}="
            ;;
         2)
            HASH="${HASH}=="
            ;;
      esac
   else
      HASH=${RAW_HASH}
   fi

   CURRENT_CERT="-----BEGIN CERTIFICATE-----"$'\n'
   CURRENT_CERT+=$(echo ${HASH} | fold -c64)
   CURRENT_CERT+=$'\n'"-----END CERTIFICATE-----"

   if echo "${CURRENT_CERT}" | openssl x509 -text > /dev/null 2>&1; then
      if [[ ${CERT_TEXT} -gt 0 ]]; then
         CURRENT_CERT_INFO=$(echo "${CURRENT_CERT}" | openssl x509 -text -noout -fingerprint -${TP_ALGORITHM} | sed -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g" -e "s/X509v3 Subject Alternative Name/${GREEN}&${NORMAL}/g")
         echo "${CURRENT_CERT_INFO}"
      else
         CURRENT_CERT_INFO=$(echo "${CURRENT_CERT}" | openssl x509 -text -noout -fingerprint -${TP_ALGORITHM} | grep -E 'Issuer:|Subject:|Validity|Not Before:|Not After :|Fingerprint' | sed -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g")

         echo "Certificate Info:"
         if echo "${CURRENT_CERT}" | openssl x509 -noout -checkend 0; then
            echo "${CURRENT_CERT_INFO}"
         else
            echo "${CURRENT_CERT_INFO}" | sed -e "s/Not Before/${RED}&/"
         fi
         if [[ ${DEBUG} -gt 0 ]]; then echo $'\t'"Certificate Hash: ${HASH}"; fi
     fi
   else
      echo "${RED}Unable to parse certificate hash${NORMAL}"
      if [[ ${DEBUG} -gt 0 ]]; then echo "${HASH}"; fi
   fi

   if [[ ${SHOW_SERVICE_IDS} -gt 0 ]]; then
      REGEX_HASH=$(echo "${RAW_HASH}" | sed -e 's/\+/\\+/g' -e 's/\$/\\$/g')
      FOUND_SERVICE_IDS=''

      for line in $(echo "${DATA}" | grep -vE '^URL:' | uniq | grep -E "ServiceID|${REGEX_HASH}" | grep -B1 ${RAW_HASH}); do
         if [[ "${line}" =~ ^ServiceID ]]; then
            CURRENT_SERVICE_ID=$(echo "${line}" | sed -e 's/ServiceID://g')
         elif $(echo "${line}" | grep ${RAW_HASH} > /dev/null); then
            if [ -z "${FOUND_SERVICE_IDS}" ]; then
               FOUND_SERVICE_IDS=$'\t'"${CURRENT_SERVICE_ID}"
            else
               FOUND_SERVICE_IDS+=$'\n\t'"${CURRENT_SERVICE_ID}"
            fi
         fi
      done

      NUM_FOUND_SERVICE_IDS=$(echo "${FOUND_SERVICE_IDS}" | sort | uniq | wc -l)

      echo "Service IDs (${NUM_FOUND_SERVICE_IDS}):"
      echo "${FOUND_SERVICE_IDS}" | sort | uniq
   fi

   if [[ ${SHOW_ENDPOINTS} -gt 0 ]]; then
      ENDPOINTS=$(echo "${DATA}" | grep -vE '^ServiceID' | grep -B1 ${RAW_HASH} | grep -E '^URL:' | sed -e 's/URL:/\t/g' | sort | uniq)
      NUM_ENDPOINTS=$(echo "${ENDPOINTS}" | wc -l)

      echo "Endpoints (${NUM_ENDPOINTS}):"
      echo "${ENDPOINTS}"
   fi

   echo "${CYAN}--------------------------------${NORMAL}"
   ((++CERT_COUNT))
done

if [[ ${VIEW_MACHINE_SSL} -gt 0 ]]; then
   if [[ ${LIVE_CHECK} -eq 0 ]]; then
      if [ "${NODE_TYPE}" = 'infrastructure' ]; then
         echo $'\n'"${YELLOW}The Machine SSL certificate is not included in an external PSC support bundle.${NORMAL}"
      else
         if [ -f ../etc/vmware-vpx/ssl/rui.crt ]; then
            MACHINE_SSL_FILE='../etc/vmware-vpx/ssl/rui.crt'
         elif [ -f ../ProgramData/VMware/vCenterServer/cfg/vmware-vpx/ssl/rui.crt ]; then
            MACHINE_SSL_FILE='../ProgramData/VMware/vCenterServer/cfg/vmware-vpx/ssl/rui.crt'
         fi

         if [ ! -z ${MACHINE_SSL_FILE} ]; then
            echo $'\n'"${CYAN}-----Machine SSL Certificate-----${NORMAL}"
            CURRENT_MACHINE_SSL_CERT_INFO=$(cat ${MACHINE_SSL_FILE} | openssl x509 -text -noout -fingerprint -${TP_ALGORITHM} | grep -E 'Issuer:|Subject:|Validity|Not Before:|Not After :|Fingerprint' | sed -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g")

            echo "Certificate Info:"
            if cat "${MACHINE_SSL_FILE}" | openssl x509 -noout -checkend 0; then
               echo "${CURRENT_MACHINE_SSL_CERT_INFO}"
            else
               echo "${CURRENT_MACHINE_SSL_CERT_INFO}" | sed -e "s/Not Before/${RED}&/"
            fi
            echo "${CYAN}---------------------------------${NORMAL}"
         else
            echo $'\n'"${YELLOW}Unable to locate the Machine SSL certificate file in the support bundle.${NORMAL}"
         fi
      fi
   else
      SSO_DOMAIN=$(/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost)
      SSO_SITE=$(/usr/lib/vmware-vmafd/bin/vmafd-cli get-site-name --server-name localhost)
      VMDIR_DC_BRANCH="dc=$(echo ${SSO_DOMAIN} | sed 's/\./,dc=/g')"
      VMDIR_MACHINE_PASSWORD=$(/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]' | grep dcAccountPassword | awk -F"  " '{print $NF}' | awk '{print substr($0,2,length($0)-2)}' | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g' | tr -d '\n' > /tmp/.vmdir_machine_account_password; chmod go-r /tmp/.vmdir_machine_account_password)
      VMDIR_MACHINE_ACCOUNT_DN=$(/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]' | grep '"dcAccountDN"' | awk -F"  " '{print $NF}' | awk '{print substr($0,2,length($0)-2)}')

      SSO_NODES=()
      PSC_NODES=$($LDAPSEARCH -LLL -h localhost -p 389 -b "ou=Domain Controllers,$VMDIR_DC_BRANCH" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y /tmp/.vmdir_machine_account_password "(objectclass=computer)" cn | grep '^cn:' | awk '{print $2}')
      PSC_COUNT=$(echo "${PSC_NODES}" | wc -l)
      VCENTER_NODES=$($LDAPSEARCH -LLL -h localhost -p 389 -b "ou=Computers,$VMDIR_DC_BRANCH" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y /tmp/.vmdir_machine_account_password "(objectclass=computer)" cn | grep '^cn:' | awk '{print $2}')
      VCENTER_COUNT=$(echo "${VCENTER_NODES}" | wc -l)
   
      for psc_node in "$PSC_NODES"; do
         if [[ ! "${SSO_NODES[@]}" =~ "$psc_node" ]]; then SSO_NODES+=($psc_node); fi
      done

      for vc_node in "$VCENTER_NODES"; do
         if [[ ! "${SSO_NODES[@]}" =~ "$vc_node" ]]; then SSO_NODES+=($vc_node); fi
      done

      rm /tmp/.vmdir_machine_account_password
      printf '\n'

      for node in "${SSO_NODES[@]}"; do
         echo "${CYAN}-----Machine SSL Certificate-----${NORMAL}"
         echo "${CYAN}${node}${NORMAL}"
         CURRENT_MACHINE_SSL_CERT_INFO=$(echo | openssl s_client -connect ${node}:443 2>/dev/null | openssl x509 -text -noout -fingerprint -${TP_ALGORITHM} 2>/dev/null | grep -E 'Issuer:|Subject:|Validity|Not Before:|Not After :|Fingerprint' | sed -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g")

         echo "Certificate Info:"
         if [ "$CURRENT_MACHINE_SSL_CERT_INFO" != "" ]; then
            if echo | openssl s_client -connect ${node}:443 2>/dev/null | openssl x509 -noout -checkend 0; then
               echo "${CURRENT_MACHINE_SSL_CERT_INFO}"
            else
               echo "${CURRENT_MACHINE_SSL_CERT_INFO}" | sed -e "s/Not Before/${RED}&/"
            fi
         else
            echo $'\t'"${YELLOW}Unable to retrieve certificate information from ${node}${NORMLA}"
         fi
         echo "${CYAN}---------------------------------${NORMAL}"
      done
   fi
fi

if [[ ${FIX} -gt 0 ]]; then
   if [[ ${LIVE_CHECK} -gt 0 ]]; then
      if [ ! -f ${LSUPDATE_SCRIPT} ]; then
         echo $'\n'"${YELLOW}The ${LSUPDATE_SCRIPT} script could not be found. Please ensure you are running this from a PSC.${NORMAL}"
      else    
         echo $'\n'"${CYAN}SSL Trust Anchor Repair${NORMAL}"
    echo "${CYAN}---------------------------------${NORMAL}"
         echo "This process will attempt to update the SSL trust anchors for Lookup Service registrations using native Lookup Service libraries. These changes should propagate to all PSCs in the SSO domain."
         echo $'\n'"${YELLOW}It is strongly recommended that you take offline snapshots of all PSCs in the SSO domain before proceeding.${NORMAL}"
         read -p $'\n'"Proceed with updating trust anchors? [Y/N]: " PROCEED
         if [ -z ${PROCEED} ]; then PROCEED_FIX="n"; else PROCEED_FIX=$(echo ${PROCEED} | awk '{print tolower(substr($0,0,1))}'); fi
         if [ ${PROCEED_FIX} == "y" ]; then
            SSO_DOMAIN=$(/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost)
            read -p $'\n'"Enter SSO admin [administrator@${SSO_DOMAIN}]: " LOGIN
            if [ -z ${LOGIN} ]; then LOGIN="administrator@${SSO_DOMAIN}"; fi
            read -s -p "Enter password for ${LOGIN}: " PASSWORD_INPUT
            PASSWORD=$(echo ${PASSWORD_INPUT} | sed "s/'/'\\\''/g")
            read -p $'\n'"Enter fingerprint of trust anchor(s) to update: " FINGERPRINT
            read -p "Enter the FQDN of the node to update: " NODE_FQDN
            if echo 'y' | openssl s_client -connect ${NODE_FQDN}:443 2>/dev/null | openssl x509 > /tmp/machine-ssl.crt; then
               if ! ${LSUPDATE_SCRIPT} --url http://localhost:${LS_PORT}/lookupservice/sdk 2>/tmp/ls_update_certs.stderr --fingerprint ${FINGERPRINT} --certfile /tmp/machine-ssl.crt --user ${LOGIN}  --password $(eval echo "'${PASSWORD}'"); then
                  echo $'\n'"${YELLOW}The ls_update_certs.py script encountered an error."
                  echo $'\n'"Please refer to /tmp/ls_update_certs.stderr for more information.${NORMAL}"
               fi
            else
               echo $'\n'"${YELLOW}Unable to obtain SSL certificate from ${NODE_FQDN}. Exiting..."
       fi
         else
            echo $'\n'"Operation aborted. Exiting..."
         fi
      fi
   else
      echo $'\n'"${YELLOW}Fixing trust anchors can only be done on a live system.${NORMAL}"
   fi
fi
