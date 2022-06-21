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

const char* PROC_STATUS_PATH = "/proc/self/status";
const int NOT_DEBUGGED_TRACERPID = 0;
const char* CMDLINE_PATH = "/proc/%d/cmdline";
const char* LD_PRELOAD = "LD_PRELOAD";
const int DEBUGGER_PRESENT = -1;

inline void detectTracerPID();
inline void detectLD_PREALOAD();
inline void detectPtrace();

// Get process name by its PID
char* getProcnameByPID(int pid)
{
    char* name = (char*)calloc(1024, sizeof(char));
    if(name)
    {
        sprintf(name, CMDLINE_PATH, pid);
        FILE* f = fopen(name, "r");
        if(f)
        {
            size_t size;
            size = fread(name, sizeof(char), 1024, f);
            if(size > 0){
                if('\n' == name[size - 1])
                    name[size - 1]= '\0';
            }
            fclose(f);
        }
    }
    return name;
}

// Reads the /proc/self/status file and TracerPid field to detect an attached debugger
void detectTracerPID()
{
    printf("TracerPID Check\n");
    FILE *fptr;
    int lineLength = 255;
    char line[lineLength];

    char* tracer;
    int tracerPid;
    char* content;

    fptr = fopen(PROC_STATUS_PATH, "r");
    
    // Cannot open the file
    if(fptr == NULL)
    {
        printf("\t[-] Error opening: %s\n", PROC_STATUS_PATH);
        exit(1);
    }

    // Reads every line in the file until finding the 'TracerPid' field
    while(fgets(line, lineLength, fptr)) 
    {
        content = strstr(line, "TracerPid");
        if(content)
            break;
    }
    fclose(fptr);

    // Use sscanf to catch the PID of the debugger process
    int ret = sscanf(content, "%s %d" , tracer, &tracerPid);
    
    // The current process is being debugged
    if (tracerPid != NOT_DEBUGGED_TRACERPID)
        printf("\t[V] The process is being Debugged by PID: %d, ProcessName: %s\n", tracerPid, getProcnameByPID(tracerPid));
    
    // The current process is not debugged
    else
        printf("\t[X] The process is NOT Debugged\n");
        
}

// Checks the LD_PRELOAD environment variable
void detectLD_PREALOAD()
{
    printf("LD_PREALOAD Check\n");
    const char* ldEnvar = getenv(LD_PRELOAD);
    
    // LD_PRELOAD environment variable is empty
    if(ldEnvar != NULL)
        printf("\t[V] %s environment variable found: %s\n", LD_PRELOAD, ldEnvar);
    else
        printf("\t[X] %s environment variable not found\n", LD_PRELOAD);
}

// Use the PTRACE_TRACEME Syscall to detect an attached debugger
void detectPtrace()
{
    printf("Ptrace Check\n");
    
    // PTRACE_TRACEME Syscall is already in used
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == DEBUGGER_PRESENT) 
        printf("\t[V] Process is being debugged\n");
    else
        printf("\t[X] Process is NOT being debugged\n");
}

int main( void )
{
    printf("\n+---------------------------+\n| Linux Anti-Debug Detection |\n+---------------------------+\n\n");
    detectPtrace();
    detectLD_PREALOAD();
    detectTracerPID();
    
    return 0;
}
