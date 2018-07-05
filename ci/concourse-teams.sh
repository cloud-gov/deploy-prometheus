#!/bin/bash

set -eux

CONCOURSE_URIS=(0.web.production-concourse.concourse-production.toolingbosh 0.web.staging-concourse.concourse-staging.toolingbosh)
TEAMS_WHITELIST="main"

for URI in "${CONCOURSE_URIS[@]}"
do
  tempfile1=$(mktemp)
  tempfile2=$(mktemp)
  IFS=$' '
  TEAMS=$(curl -s http://"$URI":8080/api/v1/teams | jq -r '.[].name')
  unset IFS
  for TEAM in $TEAMS
  do
    extra_team=1
    if echo "${TEAM}" | grep -Fxf <(echo "${TEAMS_WHITELIST}"); then
      extra_team=0
    fi
    echo "concourse_extra_team{team=\"${TEAM}\"} ${extra_team}" >> "${tempfile1}"
  done
  curl -X PUT --data-binary "@${tempfile1}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_extra_teams/concourse_url/${URI}"

  for TEAM in "${TEAMS_WHITELIST[@]}"
  do
    expected_team_missing=1
    if echo "${TEAM}" | grep -Fxf <(echo "${TEAMS}"); then
      expected_team_missing=0
    fi
    echo "concourse_expected_team_missing{team=\"${TEAM}\"} ${expected_team_missing}" >> "${tempfile2}"
  done
  curl -X PUT --data-binary "@${tempfile2}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_expected_teams/concourse_url/${URI}"
  rm -f "${tempfile1}"
  rm -f "${tempfile2}"
done
