#!/bin/bash

set -eux

tempfile=$(mktemp)

CONCOURSE_URIS="ci.fr.cloud.gov ci.fr-stage.cloud.gov"
for URI in ${CONCOURSE_URIS}
do
  AUTHURL=$(curl -sL https://"$URI"/api/v1/teams/main/auth/methods | jq -r '.[].auth_url' | grep oauth)
  has_opslogin=0
  if curl -s "$AUTHURL" | grep "opslogin.fr.cloud.gov" > /dev/null
  then
    has_opslogin=1
  fi
  echo "concourse_has_opslogin{instance=\"${URI}\"} ${has_opslogin}" >> "${tempfile}"
done

curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_opslogin"
curl --data-binary "@${tempfile}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_opslogin"
echo "concourse_has_opslogin_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_opslogin/instance/lastcheck"

rm -f "${tempfile}"