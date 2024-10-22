/*

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

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <sys/ptrace.h>

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif

const char *PROC_STATUS_PATH = "/proc/self/status";
const int NOT_DEBUGGED_TRACERPID = 0;
const char *CMDLINE_PATH = "/proc/%d/cmdline";
const char *LD_PRELOAD = "LD_PRELOAD";
const int DEBUGGER_PRESENT = -1;

inline void detectTracerPID();
inline void detectLD_PRELOAD();
inline void detectPtrace();

// Get process name by its PID
char *getProcnameByPID(int pid)
{
    char *name = (char*)calloc(1024, sizeof(char));
    if (name == NULL) {
        return "Null";
    }
        
    sprintf(name, CMDLINE_PATH, pid);
    FILE *f = fopen(name, "r");
    if (f == NULL) {
        return "Null";
    }

    size_t size = 0;
    size = fread(name, sizeof(char), 1024, f);
    if (size <= 0) {
        fclose(f);
        return "Null";
    }

    if ('\n' == name[size - 1]) {
        name[size - 1]= '\0';
    }
    fclose(f);

    return name;
}

// Reads the /proc/self/status file and TracerPid field to detect an attached debugger
void detectTracerPID()
{
    printf("TracerPID Check\n");
    FILE *fptr;
    int lineLength = 255;
    char line[lineLength];

    int tracerPid = -1;

    fptr = fopen(PROC_STATUS_PATH, "r");    
    if (fptr == NULL) {
        printf("\t[-] Error opening: %s\n", PROC_STATUS_PATH);
        return;
    }

    // Reads every line in the file until finding the 'TracerPid' field
    while (fgets(line, lineLength, fptr)) {
        if (strstr(line, "TracerPid")) {
            sscanf(line, "%*s %d", &tracerPid);
            break;
        }
    }
    fclose(fptr);

    
    if (tracerPid == NOT_DEBUGGED_TRACERPID) {
        printf("\t[X] The process is NOT Debugged\n");
        return;
    }

    // The current process is being debugged
    char *procName = getProcnameByPID(tracerPid);
    printf("\t[V] The process is being Debugged by PID: %d, ProcessName: %s\n", tracerPid, procName);
    free(procName);
}

// Checks the LD_PRELOAD environment variable
void detectLD_PRELOAD()
{
    printf("LD_PREALOAD Check\n");
    const char *ldEnvar = getenv(LD_PRELOAD);
    
    // LD_PRELOAD environment variable is empty
    if (ldEnvar != NULL) {
        printf("\t[V] %s environment variable found: %s\n", LD_PRELOAD, ldEnvar);
    } else {
        printf("\t[X] %s environment variable not found\n", LD_PRELOAD);
    }
}

// Use the PTRACE_TRACEME Syscall to detect an attached debugger
void detectPtrace()
{
    printf("Ptrace Check\n");
    
    // PTRACE_TRACEME Syscall is already in used
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == DEBUGGER_PRESENT) {
        printf("\t[V] Process is being debugged\n");
    } else {
        printf("\t[X] Process is NOT being debugged\n");
    }
}

void runAntiDebugChecks()
{
    printf("\n+---------------------------+\n| Linux Anti-Debug Detection |\n+---------------------------+\n\n");
    detectPtrace();
    detectLD_PRELOAD();
    detectTracerPID();
}
