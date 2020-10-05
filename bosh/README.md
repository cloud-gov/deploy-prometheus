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

## NessusManagerLicenseInvalid
### Source data:
https://github.com/18F/cg-nessus-manager-boshrelease/blob/master/jobs/nessus-manager/templates/bin/health.sh#L4
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L209
### Guidance:
Nessus manager is reporting a license issue. See https://cloud.gov/docs/ops/runbook/troubleshooting-nessus/ for more details.

## NessusPluginsOutdated
### Source data:
https://github.com/18F/cg-nessus-manager-boshrelease/blob/master/jobs/nessus-manager/templates/bin/health.sh#L7
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L220
### Guidance:
Nessus plugins have not been updated in over 7 days. Outdated plugins will eventually cause recently published vulnerabilities to go undetected. See https://cloud.gov/docs/ops/runbook/troubleshooting-nessus/ for more details.

## NessusScandeleteFailing
### Source data:
https://github.com/18F/cg-nessus-manager-boshrelease/blob/master/jobs/nessus-manager/templates/bin/emit-scans.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L220
### Guidance:
emit-scans.sh was unable to delete old scans for the past 2 days. See https://cloud.gov/docs/ops/runbook/troubleshooting-nessus/ for more details.

## UAAClientAuditUnexpectedClient
### Source data:
https://github.com/18F/cg-deploy-cf/blob/master/ci/uaa-client-audit.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L247
### Guidance:
An unexpected UAA Client has been detected on this UAA. Review the UAA Client name and usage, and add the client in https://github.com/18F/cg-deploy-cf/blob/master/bosh/opsfiles/clients.yml if necessary.

If you cannot identify the UAA Client detected follow the security incident response guide.

## UAAClientAuditNotRunning
### Source data:
https://github.com/18F/cg-deploy-cf/blob/master/ci/uaa-client-audit.sh
### Rule body:
https://github.com/18F/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L263
### Guidance:
UAA Client audits have not run in this environment for more then 2 hours. Check recent builds for `uaa-client-audit-*` in https://ci.fr.cloud.gov/teams/main/pipelines/deploy-cf-deployment for more details.

## UAAMonitorAccountCreation
### Source data:
https://github.com/cloud-gov/cg-deploy-cf/blob/master/ci/uaa-monitor-account-creation.sh
### Rule body:
https://github.com/cloud-gov/cg-deploy-prometheus/blob/master/bosh/opsfiles/rules.yml#L261
### Guidance:
UAA Monitor Account Creation monitors the number of new accounts in the past four days and alerts if there are more than 50. Check recent builds for `uaa-monitor-account-creation` in https://ci.fr.cloud.gov/teams/main/pipelines/deploy-cf-deployment for more details.

## Prometheus seems to be down or hung!
### Source data:
https://github.com/18F/cg-deploy-cf/blob/master/ci/prometheus-down.sh
### Guidance:
- This alert is run by concourse, which checks externally that prometheus is answering queries, that data is getting into concourse, and that the alertmanager process is running.
- This alert will get triggered if the check is unable to query the prometheus API, if the alertmanager is not responding on it's port, or if it cannot find data timestamped less than 600 seconds in the past.  There are a few queries built into the script, though these may be overridden in the job to have more.
- Go look at Prometheus and/or it's alertmanager.  It may be down or stuck, and thus other prometheus-based alerts may not be happening!

## [TEMPLATE AlertName]
### Source data:
[link to: prometheus exporter, script for push gateway, or log file]
### Rule body:
[link to rule body in github]
### Guidance:
- [What does this alert typically mean]
- [What are common causes]
- [How might you remediate these causes]
