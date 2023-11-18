#!/bin/bash
cd `dirname $0` || exit 1
mkdir -p ../data
wget --no-proxy https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv --directory-prefix=../data
