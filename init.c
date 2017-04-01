#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <comp421/hardware.h>
#include <comp421/yalnix.h>

int
main() {
    printf("Init Process Initialized.\n");
    printf("PID: %d\n", GetPid());
    while(1){
        printf("init is running\n");
        Pause();
    }
    Exit(0);
}