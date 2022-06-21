import re
from subprocess import check_output
import os
import sys

BANNER = """

################################################################
#                                                              #
#                                                              #
#     _____          _       ______   ______                   #
#    |_   _|        / \     |_   _ `.|_   _ `.                 #
#      | |         / _ \      | | `. \ | | `. \                #
#      | |   _    / ___ \     | |  | | | |  | |                #
#     _| |__/ | _/ /   \ \_  _| |_.' /_| |_.' /                #
#    |________||____| |____||______.'|______.'                 #
#                                                              #
#    Linux Anti-Debugging Detection                            #
#                                                              #
#    Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.   #
################################################################

"""
LD_PRELOAD = "LD_PRELOAD"
PROC_STATUS_PATH = "/proc/{}/status"
TRACERPID_REGEX = "TracerPID:\s+(\d+)\s*"
LEGIT_TRACERPID = 0
PTRACE_SYSCALL_OPCODES = b"\x65\x00\x00\x00\x0F\x05"

# Checks if founds a PTRACE_TRACEME Syscall is the code
def detectPTRACESyscall(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    detected = re.findall(PTRACE_SYSCALL_OPCODES, data)
    if detected:
        print("\t[-] PTRACE_TRACEME Syscall Detected {} times".format(len(detected)))
    else:
        print("\t[-] PTRACE_TRACEME Syscall not found")

# Checks if LD_PRELOAD environment variable contains the file
# If so, it meens that the file will run before every process in the system
def detectLD_PRELOAD(filepath):
    filename = filepath.split('/')[-1]
    ld_preload_env = os.getenv(LD_PRELOAD)
    if ld_preload_env:
        detected = re.findall(filename, ld_preload_env)
        if detected:
            print("\t[-] Filename detected in LD_PRELOAD environmet variable")
        else:
            print("\t[-] Filename NOT found in LD_PRELOAD environment variable")
    else:
        print("\t[-] Filename NOT found in LD_PRELOAD environment variable")
        
# Checks if the file is running under debugger
def detectTracerID(filepath):
    filename = filepath.split('/')[0]
    pid = getPIDFromName(filename)
    with open(PROC_STATUS_PATH, 'r') as f:
        content = f.read()
    
    tracerpid = re.findall(TRACERPID_REGEX, content)
    if tracerpid:
        if not(tracerpid[0] == LEGIT_TRACERPID):
            debuggerProcName = getNameFromPID(tracerpid[0])
            print("\t[-] Process is being debbuged by process: {} with PID: {}".format(debuggerProcName,tracerpid[0]))
        else:
            print("\t[-] Process is NOT being debbuged")
    else:
        print("\t[-] Process is NOT being debbuged")

# Get PID from procname
def getPIDFromName(procname):
    return int(check_output(['pidof', '-s', procname]))

# Get procname from PID
def getNameFromPID(pid):
    return check_output(['ps', '-p', pid, '-o', 'comm='])

def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print("Usage: python {} <filepath>".format(sys.argv[0]))
        sys.exit()

    filepath = sys.argv[1]
    detectPTRACESyscall(filepath)
    detectLD_PRELOAD(filepath)
    detectTracerID(filepath)
