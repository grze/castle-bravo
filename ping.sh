#!/bin/bash
ping -U -n -q -i .2 -c 5 -w 60 -W 1 ${@} | awk '/^PING/ || /^rtt/'

