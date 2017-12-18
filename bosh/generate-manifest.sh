#!/bin/bash

set -e

which spruce > /dev/null 2>&1 || {
  echo "Aborted. Please install spruce by following https://github.com/geofffranks/spruce#installation" 1>&2
  exit 1
}

path="$(dirname $0)"

SPRUCE_FILE_BASE_PATH=prometheus-config spruce merge \
  "$path/deployment.yml" \
  "$path/jobs.yml" \
  "$@"
