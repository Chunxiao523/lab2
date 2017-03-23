#include <comp421/yalnix.h>
#include <comp421/hardware.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>



int free_page = 0;
struct pte *process_page_table;