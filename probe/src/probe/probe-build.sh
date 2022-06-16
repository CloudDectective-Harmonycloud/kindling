#!/bin/sh
commit_ts=`git log -1 --format="%ct"`
commit_time=`date -d@$commit_ts +"%Y-%m-%d %H:%M:%S"`
current_time=`date +"%Y-%m-%d %H:%M:%S"`
git_version=`git log -1 --format="%h"`
sed  s/MYVERSION/"version: $git_version commit: $commit_time build: $current_time"/g version.h.tmp > version.h
echo "Git commit:" $commit_ts

