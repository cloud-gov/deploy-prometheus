# 18F cloud.gov prometheus alerts
alerts for cloud.gov prometheus deployment

# Reviewing cloud.gov alerts (prometheus)
This document contains notes for reviewing each type of alert fired in PagerDuty. It is not meant to be an exhaustive playbook, but to give initial guidance for how to configure and triage each type.

## AWSLogsCheckNotRunning
### Source data:
https://github.com/18F/cg-deploy-prometheus/blob/master/ci/awslogs.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/alerts/awslogs.alerts
### Guidance:
The concourse job to run awslogs-check is not running and no longer emitting logs to prometheus. Check recent builds of awslogs-check in https://ci.fr.cloud.gov/teams/main/pipelines/deploy-prometheus?groups=checks for more details.

## AWSMFADisabled
### Source data:
https://github.com/18F/cg-deploy-prometheus/blob/master/ci/aws-mfa.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/alerts/aws_iam_mfa.alerts
### Guidance:
An AWS user does not have MFA enabled for their account. Remind them to enable MFA for their account through the AWS console at https://console.amazonaws-us-gov.com/iam?region=us-gov-west-1 .

If you cannot identify the AWS user flagged follow the security incident response guide.

## AWSMFANotRunning
### Source data:
https://github.com/18F/cg-deploy-prometheus/blob/master/ci/aws-mfa.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/alerts/aws_iam_mfa.alerts
### Guidance:
The concourse job to run aws-mfa-check is not running and no longer emitting logs to prometheus. Check recent builds of aws-mfa-check in https://ci.fr.cloud.gov/teams/main/pipelines/deploy-prometheus?groups=checks for more details.

## BOSHJobEphemeralDiskPredictWillFill
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
The ephemeral disk for a bosh managed AWS instance is predicted to fill soon. Review the instance noted and correlate with whatever activity/deploy is filling the disk, adjusting the appropriate task or ephemeral disk size to remediate.

Jobs such as acceptance tests may fire this alert with some frequency as disk usage can change frequently throughout tests.

## BOSHJobExtentedUnhealthy
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
A bosh managed AWS instance has been in an unhealthy state for more than 30 minutes. Check service health on the instance indicated and the relevant logs for each service.

Bosh health alerts are often related to long running deploys or issues in the deploy when changes have been made. Check recent build logs in concourse for more details.

## BOSHJobHighCPULoad
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
A bosh managed AWS instance is using more than (50%?) of total CPU for 10 minutes. Check processes on the instance indicated and change instance type in the relevant deployment if necessary.

## BOSHJobLowFreeRam
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
A bosh managed AWS instance is using more than (90%) of total RAM for 10 minutes. Check processes on the instance indicated and change instance type in the relevant deployment if necessary. Low free RAM for on instances with memory resident data stores (redis, influx, elastic, etc.) may present an opportunity to tune/prune unnecessary records.

## BOSHJobSystemDiskPredictWillFill
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
The system disk for a bosh managed AWS instance is predicted to fill soon. Review the instance noted and correlate with whatever activity/deploy is filling the disk, adjusting the appropriate task or system disk size to remediate.

## BOSHJobUnhealthy
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
A bosh managed AWS instance is in an unhealthy state. Check service health on the instance indicated and the relevant logs for each service.

Bosh health alerts are often related to long running deploys or issues in the deploy when changes have been made. Check recent build logs in concourse for more details.

## BoshUnknownInstanceExpired
### Source data:
https://github.com/18F/cg-deploy-bosh/blob/master/cronjobs/unknown-vms.sh
### Rule body:
https://github.com/bosh-prometheus/prometheus-boshrelease/tree/master/jobs/bosh_alerts/templates
### Guidance:
An AWS instance which the relevant bosh director doesn’t know about has been detected. This can happen when non-bosh-managed infrastructure (ELBs) are reprovisioned and change IPs, or during bosh deployments when actual AWS instances are slightly out of sync from bosh inventory. Review the indicated instance in the AWS console and whitelist if necessary.

If you cannot identify the AWS instance flagged follow the security incident response guide.

## BrokeredElasticsearchAlive
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/alerts/kubernetes_broker.alerts
### Guidance:
A kubernetes brokered elasticsearch instance has not responded for over 5 minutes. Review the relevant kubernetes pod status and logs for more details.

## BrokeredElasticsearchHealthy
### Source data:
https://github.com/bosh-prometheus/bosh_exporter
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/alerts/kubernetes_broker.alerts
### Guidance:
A kubernetes brokered elasticsearch instance has been unhealthy for over 5 minutes. Review the relevant kubernetes pod status and logs for more details.

## [TEMPLATE AlertName]
### Source data:
[link to: prometheus exporter, script for push gateway, or log file]
### Rule body:
[link to rule body in github]
### Guidance:
- [What does this alert typically mean]
- [What are common causes]
- [How might you remediate these causes]
