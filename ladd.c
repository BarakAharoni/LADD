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
#include <sys/ptrace.h>

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME          0
#endif
#define PTRACE_DEBUGGER_PRESENT -1

#define NOT_DEBUGGED_TRACERPID  0

#define PROCNAME_MAX_SIZE       1024
#define CMDLINE_MAX_PATH        64
#define TRACER_LINE_MAX_SIZE    255

#define TRACERPID_FIELD_NAME    "TracerPid"
#define LD_PRELOAD_ENV          "LD_PRELOAD"
#define PROC_STATUS_PATH        "/proc/self/status"
#define CMDLINE_PATH_FORMAT     "/proc/%d/cmdline"

// Get process name by its PID
static char *get_procname_by_pid(int pid)
{
    char path[CMDLINE_MAX_PATH];
    snprintf(path, sizeof(path), CMDLINE_PATH_FORMAT, pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;
    }

    char *name = calloc(PROCNAME_MAX_SIZE, 1);
    if (!name) {
        fclose(f);
        return NULL;
    }

    size_t size = fread(name, 1, PROCNAME_MAX_SIZE - 1, f);
    fclose(f);

    if (size == 0) {
        free(name);
        return NULL;
    }

    name[size] = '\0';
    return name;
}

// Reads the /proc/self/status file and TracerPid field to detect an attached debugger
static void detect_tracer_pid()
{
    printf("TracerPID Check\n");
    FILE *fptr;
    char line[TRACER_LINE_MAX_SIZE];

    int tracerPid = -1;

    fptr = fopen(PROC_STATUS_PATH, "r");    
    if (fptr == NULL) {
        printf("\t[-] Error opening: %s\n", PROC_STATUS_PATH);
        return;
    }

    // Reads every line in the file until finding the 'TracerPid' field
    while (fgets(line, TRACER_LINE_MAX_SIZE, fptr)) {
        if (strstr(line, TRACERPID_FIELD_NAME)) {
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
    char *procName = get_procname_by_pid(tracerPid);
    printf("\t[V] The process is being Debugged by PID: %d, ProcessName: %s\n", tracerPid, procName);
    free(procName);
}

// Checks the LD_PRELOAD environment variable
static void detect_ld_preload()
{
    printf("LD_PREALOAD Check\n");
    const char *ldEnvar = getenv(LD_PRELOAD_ENV);

    // LD_PRELOAD environment variable is empty
    if (!ldEnvar || *ldEnvar == '\0') {
        printf("\t[X] %s environment variable not found\n", LD_PRELOAD_ENV);
        return;
    }

    printf("\t[V] %s environment variable found: %s\n", LD_PRELOAD_ENV, ldEnvar);
}

// Use the PTRACE_TRACEME Syscall to detect an attached debugger
static void detect_ptrace()
{
    printf("Ptrace Check\n");

    // PTRACE_TRACEME Syscall is already in used
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) != PTRACE_DEBUGGER_PRESENT) {
        printf("\t[X] Process is NOT being debugged\n");
        return;
    }

    printf("\t[V] Process is being debugged\n");
}

__attribute__((constructor))
static void ladd_init()
{
    printf("\nStarting Linux Anti-Debug Detection\n");
    detect_ptrace();
    detect_ld_preload();
    detect_tracer_pid();
}
