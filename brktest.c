#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <comp421/yalnix.h>
#include <comp421/hardware.h>

int
main()
{
    void *currbreak;
    char *new;

    currbreak = sbrk(0);

    currbreak = (void *)UP_TO_PAGE(currbreak);
    currbreak++;
    currbreak = (void *)UP_TO_PAGE(currbreak);
    fprintf(stderr, "sbrk(0) = %p,  %d\n", currbreak, Brk(currbreak));
    if (Brk(currbreak)) {
        fprintf(stderr, "Brk %p returned error\n", currbreak);
        Exit(1);
    }
    fprintf(stderr, "This is called \n", currbreak);

    currbreak++;
    currbreak = (void *)UP_TO_PAGE(currbreak);

    if (Brk(currbreak)) {
        fprintf(stderr, "Brk %p returned error\n", currbreak);
        Exit(1);
    }
    fprintf(stderr, "This is called \n", currbreak);
    new = malloc(10000);

    Exit(0);
}
