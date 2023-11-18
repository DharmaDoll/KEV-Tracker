#!/bin/bash
cd `dirname $0` || exit 1
mkdir -p ../data
 
current=$(date +"%Y")
from=$(date -d "-13 years" +"%Y")
for year in $(seq $from $current); do
    wget --no-proxy https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${year}.json.zip --directory-prefix=../data
done
unzip -o -d ../data "../data/*.zip" 
rm ../data/*.zip
