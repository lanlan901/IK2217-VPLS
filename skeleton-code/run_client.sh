#!/bin/bash
iperf3 -c $1  -n 1K -M 1000 --logfile result.txt 2>&1 /dev/null
