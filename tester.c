#include <dlfcn.h>
#include <stdio.h>

int main()
{
    void *handle = dlopen("./libladd.so", RTLD_LAZY);
    if (!handle) {
        printf("Error loading library: %s\n", dlerror());
        return 1;
    }

    void (*runAntiDebugChecks)() = dlsym(handle, "runAntiDebugChecks");
    if (!runAntiDebugChecks) {
        printf("Error finding function: %s\n", dlerror());
        return 1;
    }

    runAntiDebugChecks();
    dlclose(handle);

    return 0;
}
