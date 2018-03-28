#!/bin/bash

set -eux

users=$(aws iam list-users | jq -r '.Users[] | select (.PasswordLastUsed) | .UserName')
mfas=$(aws iam list-virtual-mfa-devices | jq -r '.VirtualMFADevices[] | .User.UserName')

tempfile=$(mktemp)

for user in ${users}; do
  has_mfa=0
  if echo "${user}" | grep -Fw "${mfas}"; then
    has_mfa=1
  fi
  echo "aws_iam_user_mfa{instance=\"${user}\"} ${has_mfa}" >> "${tempfile}"
done

curl -X PUT --data-binary @${tempfile} "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/aws_iam"
echo "aws_iam_user_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/aws_iam/instance/lastcheck"

rm -f "${tempfile}"
