#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstatp  Count some PID's VFS calls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: vfsstatp [-h] [-C] [-r MAXROWS] [-p PID] [interval] [count]
#
# This tools was made by mostly copy-pasting code from the BCC tools vfsstat
# and biotop.
#
# vfsstat: https://github.com/iovisor/bcc/blob/master/tools/vfsstat.py
# biotop: https://github.com/iovisor/bcc/blob/master/tools/biotop.py
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv
import argparse
from subprocess import call

# arguments
examples = """examples:
    ./vfsstatp             # count some PID's VFS calls per second
"""
parser = argparse.ArgumentParser(
    description="Count some PID's VFS calls per second.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")

args = parser.parse_args()
countdown = int(args.count)
maxrows = int(args.maxrows)
debug = 0
clear = not int(args.noclear)

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
enum stat_types {
    S_READ = 1,
    S_WRITE,
    S_FSYNC,
    S_OPEN,
    S_CREATE,
    S_MAXSTAT
};

// for saving process info by request
struct who_t {
    u32 pid;
    char name[16];
};

// the value of the output summary
struct val_t {
    u64 read;
    u64 write;
    u64 fsync;
    u64 open;
    u64 create;
    u64 maxstat;
};

BPF_HASH(counts, struct who_t, struct val_t);

static void stats_try_increment(int key) {

    struct who_t who = {};
    u32 pid;

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        pid = bpf_get_current_pid_tgid() >> 32;
        who.pid = pid;
    }

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&who, &zero);

    if (valp) {
        switch (key) {
            case S_READ:
                lock_xadd(&valp->read, 1);
                break;
            case S_WRITE:
                lock_xadd(&valp->write, 1);
                break;
            case S_FSYNC:
                lock_xadd(&valp->fsync, 1);
                break;
            case S_OPEN:
                lock_xadd(&valp->open, 1);
                break;
            case S_CREATE:
                lock_xadd(&valp->create, 1);
                break;
            case S_MAXSTAT:
                lock_xadd(&valp->maxstat, 1);
                break;
            default:
                break;
        }
    }
}
"""

bpf_text_kprobe = """
void do_read(struct pt_regs *ctx) { stats_try_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_try_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_try_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_try_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_try_increment(S_CREATE); }
"""

bpf_text_kfunc = """
KFUNC_PROBE(vfs_read)         { stats_try_increment(S_READ); return 0; }
KFUNC_PROBE(vfs_write)        { stats_try_increment(S_WRITE); return 0; }
KFUNC_PROBE(vfs_fsync_range)  { stats_try_increment(S_FSYNC); return 0; }
KFUNC_PROBE(vfs_open)         { stats_try_increment(S_OPEN); return 0; }
KFUNC_PROBE(vfs_create)       { stats_try_increment(S_CREATE); return 0; }
"""

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc
else:
    bpf_text += bpf_text_kprobe

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', """
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %s) {
        return;
    }
    """ % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event="vfs_read",         fn_name="do_read")
    b.attach_kprobe(event="vfs_write",        fn_name="do_write")
    b.attach_kprobe(event="vfs_fsync_range",  fn_name="do_fsync")
    b.attach_kprobe(event="vfs_open",         fn_name="do_open")
    b.attach_kprobe(event="vfs_create",       fn_name="do_create")

# stat column labels and indexes
stat_types = {
    "READ": 1,
    "WRITE": 2,
    "FSYNC": 3,
    "OPEN": 4,
    "CREATE": 5
}

# output
exiting = 0 if args.interval else 1
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        call("clear")
    else:
        print()

    print("time: %-8s" % strftime("%H:%M:%S"))
    print("{:<7} {:<7} {:<7} {:<7} {:<7} {:<7} {:<7} {:<16} ".format(
        "PID", "READ", "WRITE", "FSYNC", "OPEN", "CREATE", "MAXSTAT", "COMM"))
    counts = b["counts"]
    line = 0
    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].write)):

        print("{:<7} {:<7} {:<7} {:<7} {:<7} {:<7} {:<7} {:<16} ".format(
            k.pid, v.read, v.write, v.fsync,
            v.open, v.create, v.maxstat, k.name.decode('utf-8', 'replace')))
        line += 1
        if line >= maxrows:
            break

    counts.clear()
    print("")

    countdown -= 1
    if exiting or countdown == 0:
        exit()
