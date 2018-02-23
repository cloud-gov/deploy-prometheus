#!/bin/bash

set -eux

tempfile1=$(mktemp)
tempfile2=$(mktemp)

CONCOURSE_URIS=(0.web.production-concourse.concourse-production.toolingbosh 0.web.staging-concourse.concourse-staging.toolingbosh)
TEAMS_WHITELIST=(main)

for URI in "${CONCOURSE_URIS[@]}"
do
  IFS=$' '
  TEAMS=$(curl -s http://"$URI":8080/api/v1/teams | jq -r '.[].name')
  unset IFS
  for TEAM in $TEAMS
  do
    extra_team=1
    if [[ " ${TEAMS_WHITELIST[*]} " == *"$TEAM"* ]];
    then
      extra_team=0
    fi
    echo "concourse_extra_team{instance=\"${URI} ${TEAM}\"} ${extra_team}" >> "${tempfile1}"
  done
  for TEAM in "${TEAMS_WHITELIST[@]}"
  do
    expected_team_missing=1
    if [[ " ${TEAMS[*]} " == *"$TEAM"* ]];
    then
      expected_team_missing=0
    fi
    echo "concourse_expected_team_missing{instance=\"${URI} ${TEAM}\"} ${expected_team_missing}" >> "${tempfile2}"
  done
done

curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_extra_teams"
curl --data-binary "@${tempfile1}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_extra_teams"
echo "concourse_extra_teams_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_extra_teams/instance/lastcheck"

curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_expected_teams"
curl --data-binary "@${tempfile2}" "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_expected_teams"
echo "concourse_expected_teams_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/concourse_expected_teams/instance/lastcheck"

rm -f "${tempfile1}"
rm -f "${tempfile2}"
