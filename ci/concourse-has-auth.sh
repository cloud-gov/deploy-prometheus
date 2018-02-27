#!/bin/bash

set -eux

CONCOURSE_URIS="0.web.production-concourse.concourse-production.toolingbosh 0.web.staging-concourse.concourse-staging.toolingbosh"
for URI in ${CONCOURSE_URIS}
do
  tempfile=$(mktemp)
  TEAMS=$(curl -s http://"$URI":8080/api/v1/teams | jq -r '.[].name')
  for TEAM in ${TEAMS}; do
    has_auth=0
    auth_type=$(curl -s "http://${URI}:8080/auth/list_methods?team_name=${TEAM}" | jq -r '.[].type')
    if [ "${auth_type}" != "none" ]; then
      has_auth=1
    fi
    echo "concourse_has_auth{team=\"${TEAM}\"} ${has_auth}" >> "${tempfile}"
  done

  curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth/concourse_url/${URI}"
  curl --data-binary "@${tempfile}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth/concourse_url/${URI}"

  rm -f "${tempfile}"
done

echo "concourse_has_auth_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth/instance/lastcheck"
