#!/bin/bash

set -eux

tempfile=$(mktemp)

CONCOURSE_URIS="0.web.production-concourse.concourse-production.toolingbosh 0.web.staging-concourse.concourse-staging.toolingbosh"
for URI in ${CONCOURSE_URIS}
do
  MYURL=$(curl -sL http://"$URI":8080/api/v1/teams/main/auth/methods | jq -r '.[].auth_url' | grep oauth)
  AUTHURL=`echo $MYURL | sed "s#https://.*cloud\.gov/\(.*\)#http://${URI}:8080/\1#"`
  has_opslogin=0
  if curl -s "$AUTHURL" | grep "opslogin.fr.cloud.gov" > /dev/null
  then
    has_opslogin=1
  fi
  echo "concourse_has_opslogin{instance=\"${URI}\"} ${has_opslogin}" >> "${tempfile}"
done

rm -f "${tempfile}"
