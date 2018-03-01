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

set -u

: ${PROMETHEUSHOST:="0.prometheus.production-monitoring.prometheus-production.toolingbosh"}
: ${ALERTMANAGERHOST:="0.alertmanager.production-monitoring.prometheus-production.toolingbosh"}
: ${QUERIES:="
  concourse_has_opslogin_lastcheck
  bosh_unknown_iaas_instance_lastcheck
  bosh_last_scrape_timestamp
  aws_iam_user_lastcheck
"}

TIME=$(date +%s)
APIOK=no
UPDATEOK=no

for QUERY in ${QUERIES} ; do
  echo "querying prometheus ${PROMETHEUSHOST} for ${QUERY}"

  QTIME=$(curl --max-time 5 -s "${PROMETHEUSHOST}":9090/api/v1/query?query="${QUERY}" \
   | jq -r '.data.result[0].value[1]' | sed 's/\..*//')


  # make sure that the curl worked (indicates that prometheus is down entirely)
  if [ ! -z "${QTIME}" ] ; then
    echo "  prometheus API gateway is UP!"
    APIOK=yes
  
    if [ "${QTIME}" = "null" ] ; then
      echo "  API is OK, but no data for ${QUERY}"
    else
      # make sure that the data is not too old (indicates that prometheus is not accepting data)
      TIMEDIFF=$((TIME - QTIME))

      if [ "${TIMEDIFF}" -lt 600 ] ; then
        echo "  data for ${QUERY} is less than 600s old"
        UPDATEOK=yes
      else
        echo "  data for ${QUERY} is greater than 600s old!"
      fi
    fi
  fi
done

# check to make sure that the alertmanager is alive
if curl --max-time 5 -s "${ALERTMANAGERHOST}":9093/ | grep title.Alertmanager./title > /dev/null ; then
  ALERTMANAGEROK=yes
else
  ALERTMANAGEROK=no
fi

# exit uncleanly so that the on_failure stuff will trigger a pagerduty alert
if [ "${APIOK}" != yes ] ; then
  echo "Terrible news everybody!  Prometheus seems to be down, since I cannot query it's API!"
  exit 1
fi

if [ "${UPDATEOK}" != yes ] ; then
  echo "Terrible news everybody!  Prometheus seems not to be getting new data, and thus is functionally down!"
  exit 2
fi

if [ "${ALERTMANAGEROK}" != yes ] ; then
  echo "Terrible news everybody!  Alertmanager is not running, so prometheus alerts are probably not geting generated!"
  exit 2
fi

echo "Good news everybody!  Prometheus seems to be UP!"