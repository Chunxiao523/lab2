#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <comp421/hardware.h>

int
main() {
	printf("Idle Process Initialized.\n");
	while(1) {
		Pause();
	}
}