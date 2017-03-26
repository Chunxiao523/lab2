#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <comp421/hardware.h>

int
main() {
    printf("Init Process Initialized.\n");
    printf("PID: %d\n", GetPid());
}