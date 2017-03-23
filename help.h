#include <comp421/hardware.h>
#include <comp421/yalnix.h>ls
#include <comp421/loadinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


typedef struct pte pte;
extern int free_page;
extern struct pte *process_page_table;