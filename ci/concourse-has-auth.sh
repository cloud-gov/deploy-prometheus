#!/bin/bash

set -eux

for URI in ${CONCOURSE_URIS}; do
  status_code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${URI}/api/v1/teams/h4x0r")
  has_auth=0
  if [ "${status_code}" == "401" ]; then
    has_auth=1
  fi
  echo "concourse_has_auth ${has_auth}" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_has_auth/concourse_url/${URI}"
done
