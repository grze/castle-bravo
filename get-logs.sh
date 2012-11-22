#! /bin/bash
#
# get-logs.sh: grab logs from all machines in the UEC test rig
#
# source definitions

. ./helper.sh

timestamp=$(date "+%Y%m%d-%H%M%S")
curDir=$(pwd)

topo=$1
if [ -z $topo ]; then
    echo "must have the topology: topo1, topo2, topo3, topo4, topo5"
    exit 1
fi

baseDir="${curDir}/rig-${topo}-logs_${timestamp}"
mkdir -p $baseDir && cd $baseDir

# get the results log
ssh ${user}@${clc}.${domain} tar -czvf results-${timestamp}.tar.gz uec-testing-scripts/results
scp ${user}@${clc}.${domain}:results-${timestamp}.tar.gz .

# get eucalyptus logs
for mach in $machines
do
    workDir=${baseDir}/${mach}
    mkdir -p $workDir
    cd $workDir
    ssh ${user}@${mach}.${domain} tar -czvf ${mach}-${timestamp}.tar.gz /var/log
    scp ${user}@${mach}.${domain}:${mach}-${timestamp}.tar.gz .
    cd $baseDir
done

cd $curDir
# tar them up
tar -cvf rig-${topo}.tar rig-${topo}-logs_${timestamp}
