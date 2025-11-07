#!/bin/bash

set -eu

bosh -d $BOSH_DEPLOYMENT_NAME ssh $BOSH_INSTANCE_NAME "sudo /var/vcap/jobs/aide/bin/post-deploy; sudo /etc/cron.hourly/run-report"