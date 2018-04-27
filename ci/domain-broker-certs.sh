#!/bin/bash

set -ex

lb_arns=()
lb_selector='.LoadBalancers[] | select(.LoadBalancerName | startswith($prefix)) | .LoadBalancerArn'
lbs=$(aws elbv2 describe-load-balancers)
for lb_arn in $(echo "${lbs}" | jq -r --arg prefix "${PREFIX}" "${lb_selector}"); do
  lb_arns+=("${lb_arn}")
done
next_token=$(echo "${lbs}" | jq -r '.NextToken // ""')
while [ -n "${next_token}" ]; do
  lbs=$(aws elbv2 describe-load-balancers --starting-token "${next_token}")
  for lb_arn in $(echo "${lbs}" | jq -r --arg prefix "${PREFIX}" "${lb_selector}"); do
    lb_arns+=("${lb_arn}")
  done
  next_token=$(echo "${lbs}" | jq -r '.NextToken // ""')
done

nlbs=0
ncerts=0
for lb_arn in "${lb_arns[@]}"; do
  lb_listener_arns=$(aws elbv2 describe-listeners --load-balancer-arn "${lb_arn}" \
      | jq -r ".Listeners[] | select(.Port == 443) | .ListenerArn")
    for lb_listener_arn in ${lb_listener_arns}; do
      nlbs=$((nlbs + 1))
      ncerts_listener=$(aws elbv2 describe-listener-certificates --listener-arn "${lb_listener_arn}" \
          | jq -r ".Certificates | length")
      ncerts=$((ncerts + ncerts_listener))
  done
done

cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/domain_broker/instance/${ENVIRONMENT}"
domain_broker_listener_count ${nlbs}
domain_broker_certificate_count ${ncerts}
EOF
