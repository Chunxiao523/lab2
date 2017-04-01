#include <comp421/hardware.h>
#include <comp421/yalnix.h>
#include <comp421/loadinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


typedef struct pte pte;
extern int free_page_num;
/*
 * Linked list used to store the free physical address
 */
typedef struct pf {
    unsigned int phys_page_num;
    struct pf *next;
} free_page;
extern free_page *phys_free_page;

unsigned long find_free_page(void);
extern int cur_brk;