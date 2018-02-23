#!/bin/bash

set -eux

tempfile=$(mktemp)

CONCOURSE_URIS="0.web.production-concourse.concourse-production.toolingbosh 0.web.staging-concourse.concourse-staging.toolingbosh"
for URI in ${CONCOURSE_URIS}
do
  TEAMS=$(curl -s https://"$URI"/api/v1/teams | jq -r '.[].name')
  for TEAM in ${TEAMS}
  do
    has_auth=0
    if curl -s https://"${URI}"/api/v1/workers | grep "not authorized" >/dev/null
    then
      has_auth=1
    fi
    echo "concourse_has_auth{instance=\"${URI}_${TEAM}\"} ${has_auth}" >> "${tempfile}"
  done
done

curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth"
curl --data-binary "@${tempfile}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth"
echo "concourse_has_auth_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth/instance/lastcheck"

rm -f "${tempfile}"
