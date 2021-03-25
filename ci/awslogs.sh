#!/bin/bash

set -eu

GLOBAL_LAST_UPDATE=0

# in seconds
ALERT_THRESHOLD=3600
STOP_THRESHOLD=5400

# monitor these log groups
cat <<EOF > /tmp/monitor_loggroups
kubernetes-production
EOF

echo "Starting log group check..."
GROUP_COUNT=0

LOG_GROUPS=$(aws logs describe-log-groups | jq -r .logGroups[].logGroupName)

group_metrics=$(mktemp)

for GROUP in ${LOG_GROUPS}; do
    LAST_UPDATE=$(aws logs describe-log-streams --log-group-name=$GROUP --order-by LastEventTime --descending --max-items 1 | jq .logStreams[].lastEventTimestamp)
    if [ -z "${LAST_UPDATE}" ] || [ "${LAST_UPDATE}" == "null" ]; then
        LAST_UPDATE=0
    fi

    NICE_GROUP=$(echo $GROUP | tr /. - | sed s/^-//)
    LAST_UPDATE=$((${LAST_UPDATE} / 1000))

    GROUP_COUNT=$((GROUP_COUNT+1))

    if [ "$LAST_UPDATE" -gt "$GLOBAL_LAST_UPDATE" ]; then
        GLOBAL_LAST_UPDATE=$LAST_UPDATE
    fi

    if ! grep "^${NICE_GROUP}$" /tmp/monitor_loggroups; then
        # send positive alerts for groups we don't want to monitor
        STATUS=0
    elif [ $(($(date +"%s") - ${LAST_UPDATE})) -gt ${ALERT_THRESHOLD} ]; then
        STATUS=1
    else
        STATUS=0
    fi

    cat <<EOF >> ${group_metrics}
awslogs_loggroup_not_logging {group="${NICE_GROUP}"} ${STATUS}
EOF

done

curl -X PUT --data-binary @${group_metrics} "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs_group"

if [ $(($(date +"%s") - ${GLOBAL_LAST_UPDATE})) -gt ${ALERT_THRESHOLD} ]; then
  STATUS=1
else
  STATUS=0
fi

# report overall log status
cat <<EOF | curl -X PUT --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs_group/instance/_GLOBAL"
awslogs_loggroup_not_logging {group="_GLOBAL"} ${STATUS}
EOF

echo "Finished group check. Checked ${GROUP_COUNT} groups."

echo "Starting instance check..."

# list all running instances
aws ec2 describe-instances --max-items 1000 | jq -r '.Reservations[].Instances[] | select(.State.Name == "running") | .InstanceId' > /tmp/active_instances

instance_metrics=$(mktemp)
target_instance=""
# Emit a metric for each entry in our heatbeat group, where host = logStreamName, and metric = seconds since last update
IFS=$'\n'
# get all the log streams that have had an ingestion in the last 4 hours, returning their name (which is conveniently the EC2 instance id) and the time the last log was ingested
for streaminfo in $(aws logs describe-log-streams --output text --max-items 1000 --order-by LastEventTime --descending --log-group-name=$HEARTBEAT_GROUP --query "logStreams[?lastIngstionTime > \`$(($(($(date +%s) - 14400)) * 1000))\`][logStreamName, lastIngestionTime]" | grep -v None); do
    aws_id=$(echo ${streaminfo} | cut -f1)
    last=$(( $(echo ${streaminfo} | cut -f2) / 1000 ))

    # if the instance is no longer running, then we don't care if it's logging
    # and make sure that we clear it from push gw See https://github.com/prometheus/pushgateway/issues/117
    if ! grep "${aws_id}" /tmp/active_instances 1>/dev/null 2>&1; then
        continue
    fi

    if [ $(($(date +"%s") - ${last})) -gt ${ALERT_THRESHOLD} ] ; then
        STATUS=1
    else
        STATUS=0
    fi

    cat <<EOF >> ${instance_metrics}
awslogs_instance_not_logging {instance_id="${aws_id}"} ${STATUS}
EOF

done

curl -X PUT --data-binary @${instance_metrics} "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs_instance"

echo "Finished instance check. Checked $(cat /tmp/active_instances | wc -l) instances."
