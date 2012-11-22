#! /bin/bash
#
# set-ssh.sh
# sets up the user's public key in the test rig
#
# needs sshpass installed

# source definitions

. ./helper.sh

if [ -f /usr/bin/sshpass]; then
    # notice this is an insecure way of using a password... change the password as needed
    SSH="sshpass -p insecure "
else
    SSH=''

for mach in $machines
do
    $SSH sftp ${user}@${mach}.${domain} << EOF
    mkdir .ssh
    chmod 700 .ssh
    put -P ${HOME}/.ssh/id_rsa.pub .ssh/${USER}.tmp
EOF
    $SSH ssh ${user}@${mach}.${domain} "cd .ssh ; cat ${USER}.tmp >> authorized_keys; chmod 600 authorized_keys; rm -f ${USER}.tmp"
done
