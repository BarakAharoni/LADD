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
    if(fptr == NULL)
    {
        printf("\t[-] Error opening: %s\n", PROC_STATUS_PATH);
        exit(1);
    }

    while(fgets(line, lineLength, fptr)) 
    {
        content = strstr(line, "TracerPid");
        if(content)
            break;
    }
    fclose(fptr);

    int ret = sscanf(content, "%s %d" , tracer, &tracerPid);
    if (tracerPid != NOT_DEBUGGED_TRACERPID)
        printf("\t[V] The process is being Debugged by PID: %d, ProcessName: %s\n", tracerPid, getProcnameByPID(tracerPid));
    else
        printf("\t[X] The process is NOT Debugged\n");
        
}

void detectLD_PREALOAD()
{
    printf("LD_PREALOAD Check\n");
    const char* ldEnvar = getenv(LD_PRELOAD);
    if(ldEnvar != NULL)
        printf("\t[V] %s environment variable found: %s\n", LD_PRELOAD, ldEnvar);
    else
        printf("\t[X] %s environment variable not found\n", LD_PRELOAD);
}

void detectPtrace()
{
    printf("Ptrace Check\n");
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == DEBUGGER_PRESENT) 
        printf("\t[V] Process is being debugged\n");
    else
        printf("\t[X] Process is NOT being debugged\n");
}

int main( void )
{
    printf("\n+---------------------------+\n| Linux Anti-Debug Detector |\n+---------------------------+\n\n");
    detectPtrace();
    detectLD_PREALOAD();
    detectTracerPID();
    
    return 0;
}