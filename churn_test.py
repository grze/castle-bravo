#!/usr/bin/python

import datetime
from time import sleep
import logging
import os, os.path
import random
import re
import string
import sys

import yaml
from twisted.internet import reactor, task
from twisted.python import usage

import myutils

class Options(usage.Options):
    optFlags = [
            ["cleanup", None, "Clean up" ],
            ]
    optParameters = [
            ["config", "c", "config.yaml", "Configuration file" ],
            ["log", "l", "debug", "log level wanted (debug, info, warning, error, critical"],
            ]


euca_describe_availability_zones = 'euca-describe-availability-zones'
euca_describe_addresses = 'euca-describe-addresses'
euca_run_instances = 'euca-run-instances'
euca_describe_instances = 'euca-describe-instances'
euca_terminate_instances = 'euca-terminate-instances'
euca_add_keypair = 'euca-add-keypair'
euca_delete_keypair = 'euca-delete-keypair'
euca_add_group = 'euca-add-group'
euca_delete_group = 'euca-delete-group'
euca_authorize = 'euca-authorize'
euca_get_console_output = 'euca-get-console-output'

class Instance(object):
    TEST_STATES = [ 'not-tested', 'being-tested', 'success', 'failed',
                    'rescheduled', 'boot-failed' ]
    TEST_MAX_RETRIES = 200

    def __init__(self, emi, user, ssh_key, group):
        self.emi = emi
        self.user = user
        self.ssh_key = ssh_key
        self.group = group
        self.id = None
        self.pub_ip = None
        self.test_state = "not-tested"
        self._test_retries = 0
        self._state = None
        self.finished = False

    def __repr__(self):
        return "<Instance: %s - %s - %s - %s- %s>" % (self.id, self.emi,
                                      self.user, self.ssh_key, self.state)

    @property
    def logger(self):
        if self.id:
            return logging.getLogger("INSTANCE %s" % (self.id))
        else:
            return logging.getLogger()

    @property
    def private_key(self):
        return self.user.private_keys[self.ssh_key]

    @property
    def state(self):
        return self._state
    @state.setter
    def state(self, value):
        self.logger.debug("State: %s" % (value))
        # The state has changed
        if self.state == "pending":
            self._test_retries += 1
            if self._test_retries > self.TEST_MAX_RETRIES:
                self.logger.error("Instance remained in pending for MAX_RETRIES, terminating instance")
                self.test_state = 'boot-failed'
                output = self.getProcessOutput(euca_terminate_instances,
                                                args= [self.id])
                output.addCallback(self.terminate)
                return
        if self._state != value:
            self.logger.debug("New state: %s => %s" % (self._state, value))
            self._state = value
            # Only trigger a test when the state has been changed to running
            if self._state == "running":
                self._test_retries = 0
            if self._state == "running" and self._test_state != 'being-tested':
                self.logger.debug("Scheduling test")
                reactor.callLater(random.randint(5,20) + random.random(),
                                 self.test)

    @property
    def test_state(self):
        return self._test_state
    @test_state.setter
    def test_state(self, value):
        self.logger.debug("Test state: %s" % (value))
        if value not in self.TEST_STATES:
            raise ValueError, "Unknow test state: %s" % (value)
        else:
            self._test_state = value

    def getProcessOutput(self, executable, args=(), timeout=60):
        self.logger.debug("Executing: %s - %s" % (executable, args))
        return self.user.getProcessOutput(executable, args, timeout)

    def start(self):
        self.logger.info("Starting instance")
        output = self.getProcessOutput(euca_run_instances,
                                        args= [self.emi['id'],
                                               '-k', self.ssh_key,
                                               '-g', self.group,
                                               '-t', self.emi['type']
                                              ])
        output.addCallbacks(self.started, self.errStarted)
        # Terminate the instance no matter what
#        reactor.callLater(12*60, self.terminate)

    def started(self, output):
        self.logger.debug("Instance start output: %s" % (output))
        started = False
        for l in output.split("\n"):
            if l.startswith('INSTANCE') and l.split()[1]:
                self.id = l.split()[1]
                self.logger.info("Started (%s/%s)" %
                                 (self.emi['type'], self.emi['id']))
                started = True
        if not started:
            self.errStarted(output)

    def errStarted(self, output):
        self.logger.error("Instance failed to start: %s" % (output))

    def test(self):
        if self.state == "pending":
            self._test_retries += 1
            if self._test_retries <= self.TEST_MAX_RETRIES:
                self.logger.error("Not running - aborting scheduled test.")
                return
            else:
                self.logger.error("Instance remained in pending for MAX_RETRIES, terminating instance")
                self.test_state = 'boot-failed'
                output = self.getProcessOutput(euca_terminate_instances,
                                                args= [self.id])
                output.addCallback(self.terminate)
                return
        if self.state != "running":
            self.logger.error("Not running - aborting scheduled test.")
            return
        self.logger.info("Testing instance: ping %s" % (self.id))
        self.test_state = "being-tested"
        self._test_retries += 1
        output = myutils.getProcessOutput('bash', ['-c', "ping -U -n -q -i .2 -c 5 -w 60 -W 1 %s | awk '/^PING/||/^rtt/' | xargs echo -n" % (self.pub_ip) ], errortoo=True)
        output.addCallback(self.test2)

    def test2(self,output=None):
        if not output or 'rtt' in output:
            self.test_state = "being-tested"
            args = ['-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=30',
                    '-o', 'Batchmode=yes',
                    '-i', self.private_key,
                    "root@%s" % (self.pub_ip),
                    "echo TEST_SUCCESS" ]                    
            self.logger.info("Testing instance: ssh %s %s" % (self.id,self.pub_ip))
            output = myutils.getProcessOutput('echo', ['TEST_SUCCESS'], errortoo=True)
            output.addCallback(self.tested)
        elif self._test_retries <= self.TEST_MAX_RETRIES:
            self.logger.warning("Rescheduling test ping (%s/%s)" %
                             (self._test_retries, self.TEST_MAX_RETRIES))
            self.test_state = "rescheduled"
            if output:
                self.logger.debug("Test output: ping %s\n%s" % (self.id,output))
            reactor.callLater(5, self.test)
        else:
            if output:
                self.logger.error("Test output: ping %s\n%s" % (self.id,output))
            self.logger.info("Test failed")
            self.test_state = "failed"
            output = self.getProcessOutput(euca_get_console_output,
                                           args = [self.id], timeout=300)
            output.addCallback(self.consoleOutput)

    def tested(self, output=None):
        if output != None and 'TEST_SUCCESS' in output:
            self.logger.info("Test successful [%s]" % self._test_retries)
            self.test_state = "success"
            self.logger.debug("Test success output: ssh %s\n%s" % (self.id,output))
            output = self.getProcessOutput(euca_terminate_instances,
                                            args= [self.id])
            output.addCallback(self.terminate)
        elif self._test_state == 'boot-failed':
            self.logger.debug("Test boot-failed output: ssh %s\n%s" % (self.id,output))
            self.test_state = "boot-failed"
            output = self.getProcessOutput(euca_terminate_instances,
                                            args= [self.id])
            output.addCallback(self.terminate)
        elif self._test_retries <= self.TEST_MAX_RETRIES:
            self.logger.warning("Rescheduling test (%s/%s)" %
                             (self._test_retries, self.TEST_MAX_RETRIES))
            self.test_state = "rescheduled"
            self.logger.debug("Test rescheduled output: ssh %s\n%s" % (self.id,output))
            reactor.callLater(5, self.test)
        else:
            self.logger.error("Test failed output: ssh %s\n%s" % (self.id,output))
            self.test_state = "failed"
            output = self.getProcessOutput(euca_get_console_output,
                                           args = [self.id], timeout=300)
            output.addCallback(self.consoleOutput)

    def consoleOutput(self, output):
       # caution -- only used when a test failed
       self.logger.warning("Console output: START")
       for aLine in re.split("\n", output):
           self.logger.warning(aLine)
       self.logger.warning("Console output: END")
       output = self.getProcessOutput(euca_terminate_instances,
                                      args= [self.id])
       output.addCallback(self.terminate)

    def terminate(self, output=None):
        if output != None and self.id in output:
            self.finished = True
            if self.id is None:
                self.state = "terminated"
                self.logger.warning("instance has already terminated, last test state=%s" % self.test_state)
                self.terminated("TERMINATED")
            else:
                output = self.getProcessOutput(euca_terminate_instances,
                                               args= [self.id])
                output.addCallback(self.terminate)
        elif self.state == "terminated" or self.finished:
            self.terminated("TERMINATED")
    
    def terminated(self, output):
        self.logger.info("Terminated")
        if self.test_state not in ( "success", "failed", "boot-failed" ):
            self.logger.warning("terminated state found while test_state = %s" %
                             (self.test_state))
            self.test_state = "failed"
        self.state = "terminated"
        self.logger.debug("terminate output: %s" % (output))

class User(object):
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("USER %s" % (self.config['id']))
        self.keypairs = []
        self.groups = []

    def __repr__(self):
        return "<User: %s>" % (self.config["id"])

    def setup(self):
        for k in self.keypair_names:
            self.logger.debug("Adding keypair %s" % (k))
            output = self.getProcessOutput(euca_add_keypair, args = [k])
            output.addCallbacks(self.keypairAdded,self.errKeypairAdded)
        for g in self.group_names:
            self.logger.debug("Adding group %s" % (g))
            output = self.getProcessOutput(euca_add_group,
                                           args = ['-d', 'UEC-test', g])
            output.addCallbacks(self.groupAdded,self.errGroupAdded)

    def errKeypairAdded(self, output):
        self.logger.debug("Keypair error: %s" % (output))

    def keypairAdded(self, output):
        self.logger.debug("Keypair added output: %s" % (output))
        key = None
        privkey_fh = None
        for l in output.split("\n"):
            if not key and l.startswith("KEYPAIR"):
                key = l.split()[1]
                self.logger.info("Keypair (%s) added" % (key))
                self.keypairs.append(key)
                privkey_fh = open(self.private_keys[key], 'w')
                os.chmod(self.private_keys[key], 0600)
                continue
            if privkey_fh:
                privkey_fh.write("%s\n" % (l))
        if privkey_fh:
            privkey_fh.close()

    def errGroupAdded(self, output):
        group = "eucatest-g0"
        self.group.append(group)
        self.logger.debug("Authorizing group %s" % (group))
        output = self.getProcessOutput(euca_authorize,
                                       args = [group,
                                               '-P', 'tcp', '-p', '22',
                                               '-s',  '0.0.0.0/0' ])
        output.addCallback(self.groupAuthorized)

    def groupAdded(self, output):
        self.logger.debug("Group added output: %s" % (output))
        for l in output.split("\n"):
            if l.startswith("GROUP"):
                group = l.split()[1]
                self.logger.info("Group (%s) added" % (group))
                self.logger.debug("Authorizing group %s" % (group))
                output = self.getProcessOutput(euca_authorize,
                                               args = [group,
                                                       '-P', 'tcp', '-p', '22',
                                                       '-s',  '0.0.0.0/0' ])
                output.addCallback(self.groupAuthorized)

    def groupAuthorized(self, output):
        self.logger.debug("Group authorize output: %s" % (output))
        for l in output.split("\n"):
            if l.startswith("GROUP"):
                group = l.split()[1]
                self.logger.info("Group %s authorized" % (group))
                self.groups.append(group)
        self.logger.info("Group (%s) added" % (group))
        self.logger.debug("Authorizing group %s" % (group))
        output = self.getProcessOutput(euca_authorize,
                                       args = [group,
                                               '-P', 'icmp', '-t', '-1:-1',
                                               '-s',  '0.0.0.0/0' ])
        output.addCallback(self.groupAuthorized2)

    def groupAuthorized2(self, output):
        self.logger.debug("Group authorize output: %s" % (output))
        for l in output.split("\n"):
            if l.startswith("GROUP"):
                group = l.split()[1]
                self.logger.info("Group %s authorized" % (group))
                self.groups.append(group)
    @property
    def ready(self):
        return len(self.keypairs) != 0 and len(self.groups) != 0

    @property
    def private_keys(self):
        ret = {}
        for k in self.keypairs:
            ret[k] = os.path.join(self.config['cred_dir'], "%s.priv" % (k))
        return ret

    @property
    def keypair_names(self):
        return [ "eucatest-k%s" % (k) for k in range(self.config['nb_keypairs'])]

    @property
    def group_names(self):
        return [ "eucatest-g%s" % (g) for g in range(self.config['nb_groups'])]

    def getProcessOutput(self, executable, args=(), timeout=60):
        myargs = [ '-c', "%s --config=%s/eucarc %s" % (
                                                executable,
                                                self.config["cred_dir"],
                                                string.join(args))]
        self.logger.debug("Running bash command: %s " % (myargs))
        return myutils.getProcessOutput('bash', myargs, timeout=timeout,
                                        env=os.environ)

    def cleanup(self):
        for k in self.keypair_names:
            self.logger.debug("Deleting keypair %s" % (k))
            output = self.getProcessOutput(euca_delete_keypair, args = [k])
            output.addCallback(self.keypairDeleted, k)
        for g in self.group_names:
            self.logger.debug("Deleting group %s" % (g))
            output = self.getProcessOutput(euca_delete_group, args = [g])
            output.addCallback(self.groupDeleted, g)

    def keypairDeleted(self, output, key):
        self.logger.info("Keypair (%s) deleted" % (key))
        self.logger.debug("Keypair deleted output: %s" % (output))

    def groupDeleted(self, output, group):
        self.logger.info("Group (%s) deleted" % (group))
        self.logger.debug("Group deleted output: %s" % (output))

def checkRessources(instances, users, admin_user):
    #logging.debug("Checking ressource availability with admin user %s"\
    #                % (admin_user))
    # logging.debug("Known instances: %s" % (instances))
    # logging.debug("Known users: %s" % (users))
    listIPs(admin_user, instances)
    output = admin_user.getProcessOutput(euca_describe_availability_zones,
                                         args= ['verbose'])
    output.addCallback(availableRessource, instances, users, admin_user)

def availableRessource(output, instances, users, admin_user):
    #logging.debug("describe-availability-zones: %s" % (output))
    # Get a list of types which have available ressource
    available_types = []
    for l in output.split("\n"):
        m = re.search(r"(\S+)\s+(\d+)\s/\s\d+", l)
        if m and int(m.group(2)) != 0:
            available_types.append(m.group(1))
#    logging.debug("Available resource types: %s" % (available_types))
    # Start one instance of an emi that has ressource available
    emi = None
    try:
        emi = random.choice(filter(lambda e: e['type'] in available_types,
                                   config['emi']))
    except IndexError:
        hi = None
#        logging.warning("Not enough resource available for registered emis: %s",
#                     config['emi'])
    if emi:
        logging.info("Creating new instance")
        u = None
        try:
            u = random.choice(filter(lambda u: u.ready, users))
        except IndexError:
            logging.debug("No user ready")
        if u:
            i = Instance(emi = emi, user = u,
                         ssh_key = random.choice(u.keypairs),
                         group = random.choice(u.groups))
            instances.append(i)
            i.start()
    if config['max_instances_to_start'] == 0 \
       or len(instances) < config['max_instances_to_start']:
        reactor.callLater(1,
                      checkRessources, instances, users, admin_user)
    else:
        logging.info("Max instances reached. Stop checking for %s" %
                     "available resource.")

def checkInstancesState(instances, admin_user):
    logging.debug("Checking instances state")
    output = admin_user.getProcessOutput(euca_describe_instances)
    output.addCallback(instancesState, instances, admin_user)

def instancesState(output, instances, admin_user):
    logging.debug("describe instance: %s", output)
    for l in output.split("\n"):
        if l.startswith('INSTANCE'):
            try:
                i_id = l.split()[1]
                i = filter(lambda i: i.id == i_id, instances)[0]
            except IndexError:
                logging.debug("Unknown instance %s - skipping" % (i_id))
                continue
            state =  l.split()[5]
            old_state = i.state
            i.state = state
            if ( state == 'terminated' or state == 'shutting-down' ) and old_state == 'pending':
              logging.warn("Failed to boot: %s %s" % (i.id,i.pub_ip))
              i.test_state = 'boot-failed'
              i.terminate() 
            pub_ip = l.split()[3]
            if pub_ip != '0.0.0.0':
                if i.pub_ip is not None:
                    if i.pub_ip != pub_ip:
                        i.logger.warning('Setting pub ip (%s, was %s)' %(pub_ip,  i.pub_ip))
                else:
                    i.logger.debug("Setting pub ip (%s)" % (pub_ip))
                i.pub_ip = pub_ip
    # Stop when the number of instances have been run and tested
    notTested = len(filter(lambda i: i.state != 'terminated', instances))
    if config['max_instances_to_start'] != 0 \
       and len(instances) >= config['max_instances_to_start'] \
       and notTested == len(filter(lambda i: i.state == 'not-tested', instances)):
        logging.info("Test run completed")
        reactor.stop()
    else:
        reactor.callLater(random.randint(5, 10) + random.random(),
                          checkInstancesState, instances, admin_user)

def cleanUp(instances, users,  wait=True):
    logging.info("Cleaning up")
    #logging.debug("Cleaning instances: %s" % (instances))
    [ i.terminate() for i in instances ]
    if wait:
        # give it 60 seconds for processing
        sleep(60)
    logging.debug("Cleaning users: %s" % (users))
    [ u.cleanup() for u in users ]

def printStats(instances, once=False):
    stats = { 'started' : len(instances) }
    for s in Instance.TEST_STATES:
        stats[s] = len(filter(lambda i: i.test_state == s, instances))
        try:
            stats["%s_rate" % (s)] = float("%.5f" \
                                     % (float(stats[s])/stats['started']))
        except ZeroDivisionError:
            stats["%s_rate" % (s)] = 0.00
        stats["%s_instances" % (s)] = [ i.id for i in instances if i.test_state == s ]
    logging.getLogger('STATS').info("Stats: %s" % (yaml.dump(stats, width=100000)))
    if not once:
        reactor.callLater(30, printStats, instances)
    else:
        for s in Instance.TEST_STATES:
            logging.getLogger('SUMMARY').info('%s=%d' % (s,  stats[s]))

def listIPs(admin_user, instances):
    ''' calls euca-describe-addresses.
    '''
    output = admin_user.getProcessOutput(euca_describe_addresses)
    output.addCallback(listIPs_listed, instances)

def listIPs_listed(output, instances):
    '''Additional sanity check: verify than IPaddresses listed by
    describe-addresses and describe-instances (saved in the 'instances' list)
    match.
    '''
#    logging.debug('ListIPs: checking coherence between e-d-addresses and e-d-instances')
    for l in output.splitlines():
        if l.find('i-') >= 0:
            try:
#                logging.debug('ListIPs: output line %s' % (l))
                i_ip = l.split()[1]
                i_id = l.split()[2]
                i = filter(lambda i: i.id == i_id, instances)[0]
            except IndexError:
                logging.debug("unknown instance %s for IP %s - skipping" % (i_id,  i_ip))
                continue
            i_pub_ip = i.pub_ip
            i_state = i.state
            try:
                if i_ip != i_pub_ip and i_state == 'running':
                    logging.warning('instance %s (%s) reports public IP %s but e-d-addresses reports IP %s'
                                   % (i_id,  i_state,  i_pub_ip,  i_ip))
            except TypeError:
                logging.debug('got the bloody TypeException again')
                continue

if __name__ == '__main__':

    LEVELS = {'debug': logging.DEBUG,
               'info': logging.INFO,
               'warning': logging.WARNING,
               'error': logging.ERROR,
               'critical': logging.CRITICAL}
    opts = Options()
    try:
        opts.parseOptions() # When given no argument, parses sys.argv[1:]
    except usage.UsageError, errortext:
        print '%s: %s' % (sys.argv[0], errortext)
        print '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)

    level = LEVELS.get(opts['log'], logging.NOTSET)

    config = yaml.load(open(opts['config']).read())

    if config.has_key('log_filename'):
        logging.basicConfig(filename= "%s.%s" % (config['log_filename'],
                     datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")),
                     format="%(asctime)s %(name)s:%(levelname)s %(message)s",
                            level=level)
    else:
        logging.basicConfig(format="%(asctime)s %(name)s %(levelname)s %(message)s", level=level)
    logging.info("log level set to " + opts['log'])
    instances = []
    # Create relevant users
    users = [ User(u) for u in config['users'] ]
    admin_user = filter(lambda u: u.config.has_key('admin')\
                                  and u.config['admin'], users)[0]
    if opts["cleanup"]:
        cleanUp(instances, users, wait=False)
    else:
        # setup users
        [ reactor.callWhenRunning(u.setup) for u in users ]
        reactor.callWhenRunning(checkRessources, instances, users, admin_user)
        reactor.callWhenRunning(checkInstancesState, instances, admin_user)
        printStats(instances)
        reactor.run()
        cleanUp(instances, users)
        printStats(instances, once=True)
