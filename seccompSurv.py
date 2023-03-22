#!/bin/python3

##########
# Author: Cedric Casper
# Created: December 20, 2022
# Last Modified: March 22, 2023
# Context: Bachelor Thesis
#
# The eBPF program took inspiration from the extremely helpful BCC/BPF reference guide at 
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md and the exitsnoop.py tool:
# https://github.com/iovisor/bcc/blob/master/tools/exitsnoop.py
#
# This program is using eBPF to log violations of Seccomp rules, triggered by Podman containers.
# There are two modes that it can use to do so:
#  - conmon (deprecated): Search the process tree of a process causing seccomp violations for a conmon process and shut down the according container
#  - pidns: Get the process' PID namespace ID and identify the container using the same PID namespace ID and shut it down.
# Up to now it is unknown which mode is faster.
#
# TODO:
#   * Implement proper python logging
#   * Speed test of 'pidns' and 'conmon' mode
#   * Implement ignore list (of container IDs)
##########

import os
import signal
import subprocess
from bcc import BPF
import argparse
import datetime
import grp, pwd

##########
# CLI argument parser
##########
parser = argparse.ArgumentParser(
	prog = 'seccompSurv',
	description = 'Shut down Podman containers that violate Seccomp rules, system wide or only certain containers.\nThere are two operation modes: "conmon" or "pidns", that both work fine. Which one is faster is still to be determined.'
)

parser.add_argument('-v', '--verbose', action='store_true', help='Turn on debug messages')
parser.add_argument('-l', '--log', action='store_true', help='Turn on logging to file')
parser.add_argument('-m', '--mode', metavar='<conmon or pidns>', choices=['conmon', 'pidns'], default='pidns', help='Set operation mode, default is "pidns". Both work, unknown which is faster')
parser.add_argument('-u', '--user', metavar='<userid>', type=int, default=-1, help='Provide user ID to only monitor container of a certain user')
parser.add_argument('-g', '--group', metavar='<groupid>', type=int, default=-1, help='Provide group ID to only monitor containers of a certain group. If --user is set, this option will be ignored')
parser.add_argument('--container-id', metavar='<container id>', help='Only monitor a certain container ID')
parser.add_argument('--conmon-pid', metavar='<pid>', type=int, default=0, help='Only monitor a certain conmon process')

args = parser.parse_args()

if args.verbose: debug = True
else: debug = False

if args.log: logging= True
else: logging = False

mode = args.mode

if args.conmon_pid:
	if mode == 'conmon': arg_conmon_pid = args.conmon_pid
	else: print("# Mode is not set to 'conmon', --conmon-pid is ignored")


##########
# Statistics
# 'miss' is only counted when flags --user, --container-id or --conmon-pid is used
##########
hits_count = 0
miss_count = 0


# ...it's such a long function chain
def time_now():
	return datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

# Filename for logging
filename = "seccompSurv_" + time_now() + ".log"


# The BPF program, written in C
if debug: print('# Preparing eBPF program...')
ebpf_prog = """
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/sched.h>


/* Data structure to save information about the traced process:
- hit is only 1 if the end of the program is reached (means, filters applied if filters were selected)
- pid and ppid to identify the container process responsible for the seccomp violation. Used for 'conmon mode'
- nsid contains PIDNS ID of the container. Used for 'PIDNS mode'
- mapped_uid and mapped_gid are the UID and GID of the in-container user, according to UID/GID map on the host
- real_uid and real_gid to identify the user at fault and shutdown the container and applying filters
- comm contains the executable name, excluding path. Useful for logging and debugging seccomp profiles
*/
struct output_data_struct {
	u32 hit;
	u32 pid;
	u32 ppid;
	u64 nsid;
	u32 mapped_uid;
	u32 mapped_gid;
	u32 real_uid;
	u32 real_gid;
	char comm[TASK_COMM_LEN]; //TASK_COMM_LEN is defined in linux/sched.h
};


/* A page size of '16' seems to be enough to not lose any data when the processing inside the python
script is too slow. But this is just an assumption...
For more information: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html and
https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#5-bpf_ringbuf_output
*/
BPF_RINGBUF_OUTPUT(output_ringbuf, 16);


/* TRACEPOINT_PROBE attaches a function defined in it's block to a certain event in a category. In this case, 
process exits should be traced to determine what caused the process to exit (ordinary exit, external signal, 
seccomp violation, etc.). The category is 'sched', the event is 'sched_process_exit' as found under
/sys/kernel/debug/tracing/events/sched/sched_process_exit
More info: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracepoints
*/
TRACEPOINT_PROBE(sched, sched_process_exit) {
	
	// Each process is defined by a structure called 'task_struct' that is defined in include/linux/sched.h:
	// https://github.com/torvalds/linux/blob/master/include/linux/sched.h
	struct task_struct *current_task = (typeof(current_task))bpf_get_current_task();
	struct output_data_struct output_data = {};
	output_data.hit = 0;

	/* Check if exited process even has Seccomp mode turned on and check for Seccomp mode 'filtered'
	0 = no Seccomp, 1 = mode 'strict', 2 = mode 'filtered'
	https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h
	When a process is killed by Seccomp (SCMP_ACT_KILL), it has a special mode 3: SECCOMP_MODE_DEAD 
    This mode is not documented in the header files, but in seccomp.c:
    https://github.com/torvalds/linux/blob/master/kernel/seccomp.c 
	*/
	if (!((current_task->seccomp.mode == 2) || (current_task->seccomp.mode == 3))) {
		return 0;
	}

	// Get received signal 
	u32 sig_info = current_task->exit_code & 0xFF;

	/* Check if process exited with signal 31 (& 0x7F part) and if it exited abnormaly: if bit at 
	sig_info & 0x80 is set to 1, it exited with CLD_DUMPED/abnormaly and not with CLD_EXITED/normaly.
	Taken from https://github.com/iovisor/bcc/blob/master/tools/exitsnoop.py
	and https://github.com/torvalds/linux/blob/master/kernel/exit.c
	*/
	if (!(((sig_info & 0x7F) == 31) && (sig_info & 0x80))) {
		return 0;
	}
		
	// Get real UID and GID of user who started the container as found in linux/user_namespace.h
	u32 real_uid = current_task->nsproxy->pid_ns_for_children->user_ns->owner.val;
	TRACE_USER // Placeholder for UID filter code. Substituted later
	output_data.real_uid = real_uid;

	u32 real_gid = current_task->nsproxy->pid_ns_for_children->user_ns->group.val;
	output_data.real_gid = real_gid;

	// Get UID and UID according to Podman uidmap and gidmap
	// Returns u64, but output_data.uid is u32 since only the first 32 bit contain the uid, rest is gid
	output_data.mapped_uid = bpf_get_current_uid_gid();
	output_data.mapped_gid = bpf_get_current_uid_gid() >> 32;

	// Userspace usually interprets tgid as pid
	output_data.pid = current_task->tgid; 
	output_data.ppid = current_task->real_parent->tgid; 

	// Get issued command
	bpf_get_current_comm(&output_data.comm, sizeof(output_data.comm));

	// Get PID namespace ID of the process which usually is also the container's PIDNS ID
	output_data.nsid = current_task->nsproxy->pid_ns_for_children->ns.inum;

	output_data.hit = 1;

	// Write output_data struct to the ringbuf
	output_ringbuf.ringbuf_output(&output_data, sizeof(output_data), 0);

	return 0;
}
"""

if args.user != -1:
	code = """
	if (real_uid != USER) {
		output_ringbuf.ringbuf_output(&output_data, sizeof(output_data), 0);
		return 0;
	}
	"""
	code = code.replace('USER', str(args.user))
	ebpf_prog = ebpf_prog.replace('TRACE_USER', code)
else:
	ebpf_prog = ebpf_prog.replace('TRACE_USER', '')

bpf = BPF(text=ebpf_prog, cflags=["-Wno-macro-redefined"])
print('# Done preparing eBPF prog.')	


# Expects: command = String list
# Returns: stdout, stderr = String; return_code = int
def run_command(cmd):
	
	process = subprocess.Popen(
		cmd,
		stdout = subprocess.PIPE,
		stderr = subprocess.PIPE,
		text = True,
	)

	stdout, stderr = process.communicate()
	return_code = process.returncode

	return stdout, stderr, return_code
	

# Expects: uid = int
# Returns: username = String
def uid_to_username(uid):
	if debug: print("# Looking for user with UID: " + str(uid))
	cmd = ['id', '-nu', str(uid)]
	stdout, stderr, exit_code = run_command(cmd)
	username = stdout.replace('\n', '').strip()

	if debug: print("# User with UID " + str(uid) + " has username " + username)
	return username


# Expects: container_ids = String list; uid = int
# Returns: Exit code = int
def podman_container_kill(container_ids, uid):
	
	username = uid_to_username(uid)
	cmd = ['sudo', '-u', username, '-i', 'podman', 'container', 'kill'] + container_ids
	stdout, stderr, exit_code = run_command(cmd)

	if stderr != '':
		print("# Something went wrong:\n" + stderr)
	else:
		print("# Killed podman container(s) with ID(s) " + stdout + "\n")
	
	return 0


# Expects: pidns_id, uid = int
# Returns: container_ids = string list
def get_containerid_by_pidns(pidns_id, uid):

	container_ids = []
	
	username = uid_to_username(uid)
	cmd = ['sudo', '-u', username, '-i', 'podman', 'ps', '--namespace', '--noheading', '--format', '{{.ID}} {{.PIDNS}}']
	stdout, stderr, exit_code = run_command(cmd)
	output = stdout.split('\n')
	output.remove('')

	for line in output:
		if str(pidns_id) in line: container_ids.append(line.split(' ')[0])
	if debug: print("# Found container(s):\n# " + str(container_ids))

	return container_ids

	
# Expects: PID of conmon process = int
# Returns: Container ID = String list
def get_containerid_by_conmon(pid):

	cmd = ['ps', '-o', 'command', str(pid)]

	stdout, stderr, return_code = run_command(cmd)

	output = stdout.split('\n')[1:] # Remove the header from ps output
	
	# Expected format of output:
	# /usr/bin/conmon --api-version <version> -c <container id> -u <container id> [...]
	output = output[0]
	container_id = output[output.index("-c") + 3:output.index("-u") - 1]
	
	if debug: print("# Container ID of conmon process: " + container_id) 
	return container_id.split()


# Expects: PID = int
# Returns: conmon PID = int
def get_conmon_pid(pid):
	
	cmd = ['pstree', '-s', '-A', '-p', str(pid)]
	
	stdout, stderr, return_code = run_command(cmd)

	output = stdout.split('\n')

	if len(output) > 2: # pstree output should only be one line (+ an empty line)
		if debug: print("\n# Something went wrong, pstree output longer than expected:\n" + str(output))
		return -1

	# Save the pstree as a list, split at the arms/branches, written as '---'
	pstree = output[0].split('---')
	
	for process in pstree:	
		if process.startswith('conmon'):
			if debug: print("\n# Found conmon process: " + process)
			return int(process[process.index('(') + 1:process.index(')')])
	
	if debug: print("\n# Something went wrong, could not find conmon process!")
	return -1


# The following assumption is made to check if a seccomp violation happened: A process that made a
# forbidden system call is - in the case of Podman - killed with signal 31, which is actually SIGSYS/
# SIGUNUSED and exited abnormaly (the bit at exit_code & 0x80 is set to 1). 
# If this is true for a process and mode is set to 'conmon', we take the PPID of the process and 
# trace the container's conmon process upwards the pstree. The command of the conmon process has a 
# container ID assigned, which we use to kill the container in a controlled manner with 'podman container kill'.
# If the mode is set to 'pidns', the container that triggered the seccomp violation is identified by it's
# PID namespace which is also used by the process causing the fault and then the container is killed.
def process_event(ctx, data, size):

	global miss_count
	global hits_count

	event = bpf['output_ringbuf'].event(data)
	comm = event.comm.decode()
	pid = event.pid
	ppid = event.ppid
	uid = event.real_uid
	gid = event.real_gid
	mapped_uid = event.mapped_uid
	mapped_gid = event.mapped_gid
	nsid = event.nsid	
	hit = event.hit

	if hit == 0:
		miss_count += 1
		return

	if args.group != -1:
		group = grp.getgrgid(args.group)[0]
		username = uid_to_username(uid)
		# See https://stackoverflow.com/questions/9323834/python-how-to-get-group-ids-of-one-username-like-id-gn
		user_groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
		if group not in user_groups:
			miss_count += 1
			return

	print("# Potential Seccomp violation spotted.\n# Issued command: " + str(comm))
	if debug: print("# Real UID and GID: " + str(uid) + " " + str(gid) + "\n# Mapped UID and GID: " + str(mapped_uid) + " " + str(mapped_gid))

	if mode == 'conmon':
		conmon_pid = get_conmon_pid(ppid)
		if (args.conmon_pid and conmon_pid != args.conmon_pid):
			miss_count += 1 # Statistics
			return

		container_id = get_containerid_by_conmon(conmon_pid)
		if (args.container_id and args.container_id not in container_id):
			miss_count += 1 # Statistics
			return

		print("# Stopping container with ID:\n# " + str(container_id))
		podman_container_kill(container_id, uid)

	# In 'pidns mode' it's possible that multiple containers share one PID namespace (see bbpodman.py).
	# If one of multiple containers violates seccomp rules, all containers are put under collective
	# suspicion and are killed. /shrug
	elif mode == 'pidns':
		container_ids = get_containerid_by_pidns(nsid, uid)
		if (args.container_id and args.container_id not in container_ids):
			miss_count += 1 # Statistics
			return

		print("# Stopping container(s) with ID(s):\n# " + str(container_ids))
		podman_container_kill(container_ids, uid)

	else:
		print("# Neither 'conmon mode' nor 'pidns mode' selected. Which should not be possible by normal means...\n# Exiting.")
		exit(0)

	hits_count += 1 # Statistics


# Main function
def main():
	
	# Create and register signal handler for controlled shutdown from outside
	def signal_handler(signum, frame):
		print('\n# Statistics:')
		print("# Hits: " + str(hits_count) + ", Miss: " + str(miss_count) + "\n# Stopping...")
		if logging:
			with open(filename, 'w') as file:
				file.write(time_now() + " Hits: " + str(hits_count) + ", Miss: " + str(miss_count))
				file.write(time_now() + " Stopping program. Adieu!\n")
		print("\n# Adieu!")
		exit(0)

	signal.signal(signal.SIGINT, signal_handler)

	print("# Start tracing seccomp violations...\n# Mode: " + mode + "\n")
	if args.user != -1: print('# Only monitoring containers of user: ' + str(args.user) + '\n')

	if logging:
		print("# Logging to: " + filename)
		with open(filename, 'w') as file:
			file.write(time_now() + " Start seccompSurv in mode '" + mode + "'")
			if args.conmon_pid:
				file.write(time_now() + " Only monitoring container of conmon process with PID " + str(args.conmon_pid))
			elif args.container_id:
				file.write(time_now() + " Only monitoring container with ID " + args.container_id)

	bpf['output_ringbuf'].open_ring_buffer(process_event)

	while 1:
		bpf.ring_buffer_poll()


if __name__ == "__main__":
	main()
