#!/bin/bash

set -eu

GLOBAL_LAST_UPDATE=0

# in seconds
ALERT_THRESHOLD=3600
STOP_THRESHOLD=5400

# monitor these log grouips
cat <<EOF > /tmp/monitor_loggroups
kubernetes-development
kubernetes-production
kubernetes-staging
EOF

echo "Starting log group check..."
GROUP_COUNT=0

LOG_GROUPS=$(aws logs describe-log-groups | jq -r .logGroups[].logGroupName)

# Clear existing metrics from all log groups
# See https://github.com/prometheus/pushgateway/issues/117
for GROUP in ${LOG_GROUPS}; do
    NICE_GROUP=$(echo $GROUP | tr /. - | sed s/^-//)
    curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/${NICE_GROUP}"
done
curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/_GLOBAL"

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

cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/${NICE_GROUP}"
awslogs_loggroup_not_logging {group="${NICE_GROUP}"} ${STATUS}
EOF

done

if [ $(($(date +"%s") - ${GLOBAL_LAST_UPDATE})) -gt ${ALERT_THRESHOLD} ]; then
    STATUS=1
else
    STATUS=0
fi

# report overall log status
cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/_GLOBAL"
awslogs_loggroup_not_logging {group="_GLOBAL"} ${STATUS}
EOF

echo "Finished group check. Checked ${GROUP_COUNT} groups."

echo "Starting instance check..."

# list all running instances
aws ec2 describe-instances --max-items 1000 | jq -r '.Reservations[].Instances[] | select(.State.Name == "running") | .InstanceId' > /tmp/active_instances

target_instance=""
# Emit a metric for each entry in our heatbeat group, where host = logStreamName, and metric = seconds since last update
IFS=$'\n'
for streaminfo in $(aws logs describe-log-streams --output text --max-items 1000 --order-by LastEventTime --descending --log-group-name=$HEARTBEAT_GROUP --query "logStreams[?lastEventTimestamp > \`$(($(($(date +%s) - 14400)) * 1000))\`][logStreamName, lastEventTimestamp]" | grep -v None); do
    aws_id=$(echo ${streaminfo} | cut -f1)
    last=$(( $(echo ${streaminfo} | cut -f2) / 1000 ))

    # if the instance is no longer running, then we don't care if it's logging
    # and make sure that we clear it from push gw See https://github.com/prometheus/pushgateway/issues/117
    if ! grep "${aws_id}" /tmp/active_instances 1>/dev/null 2>&1; then
        curl -X DELETE "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/${aws_id}"
        continue
    fi

    # stop an instance if it hasn't been logging for a while (see below
    # note: this intentionally only stops one instance, so in case of an awslogs failure
    # instances will be gradually stopped (one each time this script is run)
    # and not destory the entire environment at once
    if [ $(($(date +"%s") - ${last})) -gt ${STOP_THRESHOLD} ] && [ -z "${target_instance}" ]; then
        target_instance=${aws_id}
        STATUS=2
    elif [ $(($(date +"%s") - ${last})) -gt ${ALERT_THRESHOLD} ] ; then
        STATUS=1
    else
        STATUS=0
    fi

cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs/instance/${aws_id}"
awslogs_instance_not_logging {instance_id="${aws_id}"} ${STATUS}
EOF

done

echo "Finished instance check. Checked $(cat /tmp/active_instances | wc -l) instances."

echo "awslogs_lastcheck $(date +'%s')" | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/awslogs"

# if we need to, stop an instance
if [ ! -z "${target_instance}" ]; then

    echo "$target_instance" > stopping/instance-id

    echo "${target_instance} is being stopped!"

    # This is commented out until we remove this functionality from riemann
    # # find a list of volumes for the instance
    # # this will also exit the program if the provided instance-id doesn't exist or is invalid
    # VOLUMES=$(aws ec2 describe-instances --instance-ids ${target_instance} --output text --query 'Reservations[].Instances[].BlockDeviceMappings[].*.VolumeId')
    # for vol in ${VOLUMES}; do
    #     echo "Snapshotting ${target_instance}/${vol}"
    #     aws ec2 create-snapshot --volume-id ${vol} --description "Created from ${target_instance} by $(hostname):${SCRIPTPATH}"
    # done

    # echo "Stopping ${target_instance}"
    # aws ec2 stop-instances --instance-ids ${target_instance}
fi
