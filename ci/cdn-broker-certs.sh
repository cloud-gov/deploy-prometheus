#!/bin/bash

set -euxo pipefail

## Calculate the days to expiration from now
function days_to_cert_expiration {
  local client=$1;
  local server=$2;
  local date_today=$(date +%s);

  ## Get expirationdate and convert to epoch
  expirationdate=$(date -d "$(: | openssl s_client -connect $client:443 -servername $server 2>/dev/null \
    | openssl x509 -text \
    | grep 'Not After' \
    | awk '{print $4,$5,$7}')" '+%s');

  ## Check the seconds to expiration from now
  seconds_to_go=$(expr $expirationdate - $date_today)\

  if ! [[ $seconds_to_go -gt 0 ]]; then
    ## Return integer less than or equal to 0
    seconds_past=$(expr $date_today - $expirationdate)
    negative_days=$(($seconds_past / 86400))
    echo $((0 - $negative_days))
  else
     ## Return integer greater than or equal to 0
    echo $(($seconds_to_go / 86400))
  fi
}

## Select and get Cloudfront instances returning ARN, & Aliases
alias_count=0
cdn_count=0
cdns_selector='.DistributionList.Items[] | select(.Aliases.Items != null) | {id:.Id,arn:.ARN,aliases:.Aliases.Items,domain:.DomainName}'
cdns=$(aws cloudfront list-distributions | jq -c "${cdns_selector}")
cdn_list=($cdns)

## Loop through list of CDN instances
cdn_certificate_expirations=""
for cdn in "${cdn_list[@]}"; do
  cdn_count=$((cdn_count + 1))
  aliases=($(echo $cdn | jq -r ".aliases[]"))
  arn=($(echo $cdn | jq -r ".arn"))
  domain=($(echo $cdn | jq -r ".domain"))
  id=($(echo $cdn | jq -r ".id"))

  for alias in "${aliases[@]}"; do
    alias_count=$((alias_count + 1))
    days_to_expire=$(days_to_cert_expiration $domain $alias)
    cdn_certificate_expirations="${cdn_certificate_expirations}"$'\n'"cdn_certificate_expiration{id=\"${id}\",arn=\"${arn}\",alias=\"${alias}\",domain=\"${domain}\"} ${days_to_expire}"
  done
done

## Create and post to prometheus
cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/domain_broker/instance/${ENVIRONMENT}"
cdn_instance_count ${cdn_count}
cdn_alias_count ${alias_count}
${cdn_certificate_expirations}
EOF
