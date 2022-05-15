# LADD
Linux Anti-Debugging Detector tool

```                                                     
     _____          _       ______   ______                   
    |_   _|        / \     |_   _ `.|_   _ `.                 
      | |         / _ \      | | `. \ | | `. \                
      | |   _    / ___ \     | |  | | | |  | |                
     _| |__/ | _/ /   \ \_  _| |_.' /_| |_.' /                
    |________||____| |____||______.'|______.'                 

```

## LD_PRELOAD environment variable
This environment variable is loaded before every library in the system (including the C runtime, libc.so). Thou, malwares can use it, by loading themselves and gain persistence using a command like `export LD_PRELOAD=/malware_path`.

## PTRACE_TRACEME Syscall
Many debuggers, like `gdb` use this syscall for attach the debugger to the target process. The `PTRACE_TRACEME` syscall can be used one time per process. Due to that reason, malwares can make a call to that syscall before the program's entry point, so no other similar syscall can be made. Or in other words, the process can not be debugged.

## /proc/{pid}/status
This file contains information about the process with the relevant PID. One of them is the `TracerPID` parameter.
When a process is running under debugger, the `TracerPID` parameter contain the PID of the parent process - the debugger. Otherwise, it will contain `0`.

## Usage
`python3 ./ladd.py {filepath}`

Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
