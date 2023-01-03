#!/bin/bash
# Author: Lemur
# Github: https://github.com/1emvr
# Email: 1emvr@protonmail.com
# 2022-10-18
 
domains=$(	
	curl -s "https://crt.sh/?q=$1&output=json" |
	jq -r '.[] | .common_name'
);
 
list=$(	
	for i in $domains;
	do host $i |
		grep "has address" |
		grep "$1" |
		cut -d " " -f1,4 >> \
		${2}-domains-list.txt;
	done
);
 
for i in $domains; 
	do echo $i; done
 
shodan init $SHODAN_API_KEY
 
for i in $list;
	do shodan host $i >> ${2}-shodaninfo.txt; done
