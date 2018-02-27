#!/bin/bash
# 
# This script checks a few known queries against the internal prometheus query
# API.  These queries are chosen because they have timestamps as their values.
# The queries and the prometheus host can be overridden with environment 
# variables.
# 
# If the query fails, then something is wrong with Prometheus's query API.
# 
# If at least one timestamp is up to date, then we know it's probably working,
# otherwise, something is jammed up inside probably.
# 
# 
# XXX If something stops the processes that generate these timestamp metrics,
# this will result in false positives.  Maybe a deploy might do this?
#

set -ux

: ${PROMETHEUSHOST:="0.prometheus.production-monitoring.prometheus-production.toolingbosh"}
: ${QUERIES:="
  concourse_has_opslogin_lastcheck
  bosh_unknown_iaas_instance_lastcheck
  bosh_last_scrape_timestamp
  aws_iam_user_lastcheck
"}

TIME=$(date +%s)
APIOK=yes
UPDATEOK=no

for QUERY in ${QUERIES} ; do
  QTIME=$(curl --max-time 5 -s "${PROMETHEUSHOST}":9090/api/v1/query?query="${QUERY}" \
   | jq -r '.data.result[0].value[1]' | sed 's/\..*//')

  # make sure that the curl worked (indicates that prometheus is down entirely)
  if [ -z "${QTIME}" ] ; then
    APIOK=no
  else
    # make sure that the data is not too old (indicates that prometheus is not accepting data)
    TIMEDIFF=$(( "${TIME}" - "${QTIME}"))

    if [ "${TIMEDIFF}" -lt 600 ] ; then
     UPDATEOK=yes
    fi
  fi
done

if [ "${APIOK}" != yes -o "${UPDATEOK}" != yes ] ; then
  # email everybody
  echo "Terrible news everybody!  Prometheus is down!"
fi
