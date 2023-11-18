#!/bin/bash
cd `dirname $0` || exit 1
mkdir -p ../data
wget --no-proxy https://epss.cyentia.com/epss_scores-current.csv.gz --directory-prefix=../data
gzip -d ../data/epss_scores-current.csv.gz
