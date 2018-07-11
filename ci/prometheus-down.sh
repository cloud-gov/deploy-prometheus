#!/bin/bash
# 
# This script checks a few known queries against the internal prometheus query
# API.  These queries are chosen because they have timestamps as their values.
# The queries and the prometheus host can be overridden with environment 
# variables.
# 
# If the query fails, then something is wrong with Prometheus's query API.
# 
# If at tsdb max timestamp is up to date, then we know it's probably working,
# otherwise, something is jammed up inside probably.
#
#

set -u

: ${PROMETHEUSHOST:="0.prometheus.production-monitoring.prometheus-production.toolingbosh"}
: ${ALERTMANAGERHOST:="0.alertmanager.production-monitoring.prometheus-production.toolingbosh"}
: ${QUERY:="prometheus_tsdb_head_max_time%7Binstance%3D\"localhost:9090\",job%3D\"prometheus\"%7D"}

TIME=$(date +%s)
APIOK=no
UPDATEOK=no

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
    # the TSDB max time switches out every 60s, so we should have something newer within 120s
    # this makes sure that prometheus is monitoring itself properly
    TIMEDIFF=$((TIME - QTIME))

    if [ "${TIMEDIFF}" -lt 120 ] ; then
      echo "  data for ${QUERY} is less than 120s old, so tsdb is timestamping properly"
      UPDATEOK=yes
    else
      echo "  data for ${QUERY} is greater than 120s old! tsdb is not timestamping properly"
    fi
  fi
fi


# check to make sure that the alertmanager is alive
if curl --max-time 5 -s "${ALERTMANAGERHOST}":9093/ | grep title.Alertmanager./title > /dev/null ; then
  echo "alertmanager seems to be responding with data on ${ALERTMANAGERHOST}:9093/"
  ALERTMANAGEROK=yes
else
  echo "alertmanager seems NOT to be responding with data on ${ALERTMANAGERHOST}:9093/!"
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
