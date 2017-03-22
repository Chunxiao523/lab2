#include <comp421/yalnix.h>
#include <comp421/hardware.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
/*
mid term
initializing interrupts, enabling virtual memory, and creating the idle and init processes.
*/


/*
 * keep tracking the location of the current break for the kernel
 */
void *kernel_cur_break; 

/*
 * flag to indicate if you have yet enabled virtual memory
 * 0: not, 1: yes
 */
int vir_mem = 0;

struct pte *kernel_page_table;
struct pte *process_page_table;

/*
 * The table used to store the interrupts
 */
typedef void (*handler)(ExceptionInfo *info); 
/* 
 * Data structure of process
 */
typedef struct pcb {
    SavedContext *ctx;
    int pid;
} pcb;

pcb *idle;

void TrapKernel(ExceptionInfo *info);
void TrapClock(ExceptionInfo *info);
void TrapIllegal(ExceptionInfo *info);
void TrapMemory(ExceptionInfo *info);
void TrapMath(ExceptionInfo *info);
void TrapTTYReceive(ExceptionInfo *info);
void TrapTTYTransmit(ExceptionInfo *info);



/*
 * The procedure named KernelStart is automatically called by the bootstrap firmware in the computer
 * initialize your operating system kernel and then return. 
 * *info. a pointer to an initial ExceptionInfo structure
 * pmem_size total size of the physical memory
 * *org_brk gives the initial value of the kernel’s “break
 * **cmd_args.containing a pointer to each argument from the boot command line
 */
void KernelStart(ExceptionInfo *info, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
	kernel_cur_break = orig_brk;
	handler *interrupt_vector_table = (handler *) calloc(TRAP_VECTOR_SIZE, sizeof(handler));
	kernel_page_table = (struct pte *)malloc(PAGE_TABLE_SIZE);
	process_page_table = (struct pte *)malloc(PAGE_TABLE_SIZE);
	/*
	 * Initialize the interrupt table
	 *
	 */
	 interrupt_vector_table[TRAP_KERNEL] = TrapKernel;
	 interrupt_vector_table[TRAP_CLOCK] = TrapClock;
	 interrupt_vector_table[TRAP_ILLEGAL] = TrapIllegal;
	 interrupt_vector_table[TRAP_MEMORY] = TrapMemory;
	 interrupt_vector_table[TRAP_MATH] = TrapMath;
	 interrupt_vector_table[TRAP_TTY_RECEIVE] = TrapTTYReceive;
	 interrupt_vector_table[TRAP_TTY_TRANSMIT] = TrapTTYTransmit;
	 int i;
	 for (i=7; i<TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table[i] = NULL;
    }
	WriteRegister(REG_VECTOR_BASE, interrupt_vector_table);


	/* 
     * Initialize the page table and page table register for region 1 and 0
     */

	WriteRegister(REG_PTR1,(RCS421RegVal)(kernel_page_table));
	long addr;
    for (addr = VMEM_1_BASE; addr<(unsigned long)(&_etext); addr+=PAGESIZE) {
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
        kernel_page_table[i].pfn = addr>>PAGESHIFT; //page frame number
        kernel_page_table[i].valid = 1;
        kernel_page_table[i].kprot = PROT_READ|PROT_EXEC;
        kernel_page_table[i].uprot = PROT_NONE;
    }
    for (; addr<(unsigned long)kernel_cur_break; addr += PAGESIZE) {
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
        kernel_page_table[i].pfn = addr>>PAGESHIFT;
        kernel_page_table[i].valid = 1;
        kernel_page_table[i].kprot = PROT_READ|PROT_WRITE;
        kernel_page_table[i].uprot = PROT_NONE;
    }

    WriteRegister(REG_PTR0, (RCS421RegVal)(process_page_table));
    for (addr = KERNEL_STACK_BASE; addr <= VMEM_0_LIMIT; addr+= PAGESIZE) {
    	i = (addr - VMEM_0_BASE)>>PAGESHIFT; //VMEM_0_BASE = 0
    	process_page_table[i].pfn = addr>>PAGESHIFT;
        process_page_table[i].valid = 1;
        process_page_table[i].kprot = PROT_READ|PROT_WRITE;
        process_page_table[i].uprot = PROT_NONE;
    }

	/* enable the virtual memory subsystem */
	WriteRegister(REG_VM_ENABLE, 1); 
	vir_mem = 1;

	/*
	 * Create idle and init process
	 */

	idle = (pcb*)malloc(sizeof(pcb));
    idle->pid = 0;
    idle->ctx=(SavedContext*)malloc(sizeof(SavedContext));

    LoadProgram("idle",cmd_args,info);

}

int SetKernelBrk(void *addr) {
	if (vir_mem == 0) {
		kernel_cur_break = addr;
	} else {
		if(addr > kernel_cur_break) {
			int i;
			/* Given a virtual page number, assign a physical page to its corresponding pte entry */
			for(i = (UP_TO_PAGE(kernel_cur_break) - VMEM_1_BASE)>>PAGESHIFT; i < (UP_TO_PAGE(addr) - VMEM_1_BASE)>>PAGESHIFT; i++) {
//				pt_r1[i].pfn = getFreePage();
//                pt_r1[i].valid = 1;
//                pt_r1[i].kprot = PROT_READ|PROT_WRITE;
//                pt_r1[i].uprot = PROT_NONE;
			}
		} else {

		}
	}
	return 0;
}
/* 
 * execute the requested the requested kernel call,
 * as indicated by the kernel call number in the code field of the ExceptionInfo
 */
void TrapKernel(ExceptionInfo *info) {
	switch((*info).code)
		{
			case YALNIX_FORK:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_EXEC:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_EXIT:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_WAIT:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_GETPID:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_BRK:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_DELAY:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_TTY_READ:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_TTY_WRITE:
				(*info).regs[0] = NULL;
				break;
			default:
            	break;
		}
}
void TrapClock(ExceptionInfo *info) {

}
void TrapIllegal(ExceptionInfo *info) {
	 printf("[TRAP_ILLEGAL] Trapped Illegal Instruction, pid %d\n", 0);
	 switch((*info).code) {
	 	case TRAP_ILLEGAL_ILLOPC:
	 		printf("Illegal opcode \n");
	 		break;
	 	case TRAP_ILLEGAL_ILLOPN:
	 		printf("Illegal operand \n");
	 		break;
	 	case TRAP_ILLEGAL_ILLADR:
	 		printf("Illegal addressing mode \n");
	 		break;
	 	case TRAP_ILLEGAL_ILLTRP:
	 		printf("Illegal software trap \n");
	 		break;
	 	case TRAP_ILLEGAL_PRVOPC:
	 		printf("Privileged opcode \n");
	 		break;
	 	case TRAP_ILLEGAL_PRVREG:
	 		printf("Privileged register \n");
	 		break;
	 	case TRAP_ILLEGAL_COPROC:
	 		printf("Coprocessor error \n");
	 		break;
	 	case TRAP_ILLEGAL_BADSTK:
	 		printf("Bad stack \n");
	 		break;
	 	case TRAP_ILLEGAL_KERNELI:
	 		printf("Linux kernel sent SIGILL \n");
	 		break;
	 	case TRAP_ILLEGAL_USERIB:
	 		printf("Received SIGILL or SIGBUS from user \n");
	 		break;
	 	case TRAP_ILLEGAL_ADRALN:
	 		printf("Invalid address alignment \n");
	 		break;
	 	case TRAP_ILLEGAL_ADRERR:
	 		printf("Non-existant physical address \n");
	 		break;
	 	case TRAP_ILLEGAL_OBJERR:
	 		printf("Object-specific HW error \n");
	 		break;
	 	case TRAP_ILLEGAL_KERNELB:
	 		printf("Linux kernel sent SIGBUS \n");
	 		break;
	 	default:
	 		break;
	 }
}
void TrapMemory(ExceptionInfo *info){

}
void TrapMath(ExceptionInfo *info) {

}
void TrapTTYReceive(ExceptionInfo *info) {

}
void TrapTTYTransmit(ExceptionInfo *info) {

}

/* Load Program */
/*
 *  Load a program into the current process's address space.  The
 *  program comes from the Unix file identified by "name", and its
 *  arguments come from the array at "args", which is in standard
 *  argv format.
 *
 *  Returns:
 *      0 on success
 *     -1 on any error for which the current process is still runnable
 *     -2 on any error for which the current process is no longer runnable
 *
 *  This function, after a series of initial checks, deletes the
 *  contents of Region 0, thus making the current process no longer
 *  runnable.  Before this point, it is possible to return ERROR
 *  to an Exec() call that has called LoadProgram, and this function
 *  returns -1 for errors up to this point.  After this point, the
 *  contents of Region 0 no longer exist, so the calling user process
 *  is no longer runnable, and this function returns -2 for errors
 *  in this case.
 */
int LoadProgram(char *name, char **args, ExceptionInfo *info) {
    int fd;
    int status;
    struct loadinfo li;
    char *cp;
    char *cp2;
    char **cpp;
    char *argbuf;
    int i;
    unsigned long argcount;
    int size;
    int text_npg;
    int data_bss_npg;
    int stack_npg;
    TracePrintf(0, "LoadProgram '%s', args %p\n", name, args);
    if ((fd = open(name, O_RDONLY)) < 0) {
        TracePrintf(0, "LoadProgram: can't open file '%s'\n", name);
        return (-1);
    }

    status = LoadInfo(fd, &li);
    TracePrintf(0, "LoadProgram: LoadInfo status %d\n", status);
    switch (status) {
        case LI_SUCCESS:
            break;
        case LI_FORMAT_ERROR:
            TracePrintf(0,
                        "LoadProgram: '%s' not in Yalnix format\n", name);
            close(fd);
            return (-1);
        case LI_OTHER_ERROR:
            TracePrintf(0, "LoadProgram: '%s' other error\n", name);
            close(fd);
            return (-1);
        default:
            TracePrintf(0, "LoadProgram: '%s' unknown error\n", name);
            close(fd);
            return (-1);
    }
    TracePrintf(0, "text_size 0x%lx, data_size 0x%lx, bss_size 0x%lx\n",
                li.text_size, li.data_size, li.bss_size);
    TracePrintf(0, "entry 0x%lx\n", li.entry);
    /*
     *  Figure out how many bytes are needed to hold the arguments on
     *  the new stack that we are building.  Also count the number of
     *  arguments, to become the argc that the new "main" gets called with.
     */
    size = 0;
    for (i = 0; args[i] != NULL; i++) {
        size += strlen(args[i]) + 1;
    }
    argcount = i;
    TracePrintf(0, "LoadProgram: size %d, argcount %d\n", size, argcount);
    /*
     *  Now save the arguments in a separate buffer in Region 1, since
     *  we are about to delete all of Region 0.
     */
    cp = argbuf = (char *)malloc(size);
    for (i = 0; args[i] != NULL; i++) {
        strcpy(cp, args[i]);
        cp += strlen(cp) + 1;
    }

    /*
     *  The arguments will get copied starting at "cp" as set below,
     *  and the argv pointers to the arguments (and the argc value)
     *  will get built starting at "cpp" as set below.  The value for
     *  "cpp" is computed by subtracting off space for the number of
     *  arguments plus 4 (for the argc value, a 0 (AT_NULL) to
     *  terminate the auxiliary vector, a NULL pointer terminating
     *  the argv pointers, and a NULL pointer terminating the envp
     *  pointers) times the size of each (sizeof(void *)).  The
     *  value must also be aligned down to a multiple of 8 boundary.
     */
    cp = ((char *)USER_STACK_LIMIT) - size;
    cpp = (char **)((unsigned long)cp & (-1 << 4)); /* align cpp */
    cpp = (char **)((unsigned long)cpp - ((argcount + 4) * sizeof(void *)));

    text_npg = li.text_size >> PAGESHIFT;
    data_bss_npg = UP_TO_PAGE(li.data_size + li.bss_size) >> PAGESHIFT;
    stack_npg = (USER_STACK_LIMIT - DOWN_TO_PAGE(cpp)) >> PAGESHIFT;

    TracePrintf(0, "LoadProgram: text_npg %d, data_bss_npg %d, stack_npg %d\n",
                text_npg, data_bss_npg, stack_npg);
    /*
     *  Make sure we will leave at least one page between heap and stack
     */
    if (MEM_INVALID_PAGES + text_npg + data_bss_npg + stack_npg +
        1 + KERNEL_STACK_PAGES >= PAGE_TABLE_LEN) {
        TracePrintf(0, "LoadProgram: program '%s' size too large for VM\n",
                    name);
        free(argbuf);
        close(fd);
        return (-1);
    }

    /*
     *  And make sure there will be enough physical memory to
     *  load the new program.
     */
    // >>>> The new program will require text_npg pages of text,
    // >>>> data_bss_npg pages of data/bss, and stack_npg pages of
    // >>>> stack.  In checking that there is enough free physical
    // >>>> memory for this, be sure to allow for the physical memory
    // >>>> pages already allocated to this process that will be
    // >>>> freed below before we allocate the needed pages for
    // >>>> the new program being loaded.
    if (text_npg + data_bss_npg + stack_npg > num_free_pages) {
        TracePrintf(0,
                    "LoadProgram: program '%s' size too large for physical memory\n",
                    name);
        free(argbuf);
        close(fd);
        return (-1);
    }
   // ExceptionStackFrame *frame = (ExceptionStackFrame *)((long)EXCEPTION_FRAME_ADDR);
    // >>>> Initialize sp for the current process to (char *)cpp.
    // >>>> The value of cpp was initialized above.
    info->sp = (char *)cpp;
    /*
     *  Free all the old physical memory belonging to this process,
     *  but be sure to leave the kernel stack for this process (which
     *  is also in Region 0) alone.
     */
    // >>>> Loop over all PTEs for the current process's Region 0,
    // >>>> except for those corresponding to the kernel stack (between
    // >>>> address KERNEL_STACK_BASE and KERNEL_STACK_LIMIT).  For
    // >>>> any of these PTEs that are valid, free the physical memory
    // >>>> memory page indicated by that PTE's pfn field.  Set all
    // >>>> of these PTEs to be no longer valid.
    for (i = MEM_INVALID_PAGES; i < KERNEL_STACK_BASE >> PAGESHIFT; i++) {
        if (region_0_pt[i].valid) {
            free_page_enq(0, i);
        }
    }
    /*
     *  Fill in the page table with the right number of text,
     *  data+bss, and stack pages.  We set all the text pages
     *  here to be read/write, just like the data+bss and
     *  stack pages, so that we can read the text into them
     *  from the file.  We then change them read/execute.
     */

    // >>>> Leave the first MEM_INVALID_PAGES number of PTEs in the
    // >>>> Region 0 page table unused (and thus invalid)
    for (i = 0; i < MEM_INVALID_PAGES; i++) {
        region_0_pt[i].valid = 0;
    }
    /* First, the text pages */
    // >>>> For the next text_npg number of PTEs in the Region 0
    // >>>> page table, initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_EXEC
    // >>>>     pfn   = a new page of physical memory
    for (i = MEM_INVALID_PAGES; i < MEM_INVALID_PAGES + text_npg; i++) {
        *brk_pn = *brk_pn + 1;
        if (free_page_deq(REGION_0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }

    /* Then the data and bss pages */
    // >>>> For the next data_bss_npg number of PTEs in the Region 0
    // >>>> page table, initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_WRITE
    // >>>>     pfn   = a new page of physical memory

    for (i = MEM_INVALID_PAGES + text_npg; i < MEM_INVALID_PAGES + text_npg + data_bss_npg; i++) {
        *brk_pn = *brk_pn + 1;
        if (free_page_deq(REGION_0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }

    /* And finally the user stack pages */
    // >>>> For stack_npg number of PTEs in the Region 0 page table
    // >>>> corresponding to the user stack (the last page of the
    // >>>> user stack *ends* at virtual address USER_STACK_LMIT),
    // >>>> initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_WRITE
    // >>>>     pfn   = a new page of physical memory

    for (i = 0; i < stack_npg; i++) {
        int index = (USER_STACK_LIMIT >> PAGESHIFT) - 1 - i;
        if (free_page_deq(REGION_0, index, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }
    /*
     *  All pages for the new address space are now in place.  Flush
     *  the TLB to get rid of all the old PTEs from this process, so
     *  we'll be able to do the read() into the new pages below.
     */
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Read the text and data from the file into memory.
     */
    if (read(fd, (void *)MEM_INVALID_SIZE, li.text_size+li.data_size)
        != li.text_size+li.data_size) {
        TracePrintf(0, "LoadProgram: couldn't read for '%s'\n", name);
        free(argbuf);
        close(fd);
        // >>>> Since we are returning -2 here, this should mean to
        // >>>> the rest of the kernel that the current process should
        // >>>> be terminated with an exit status of ERROR reported
        // >>>> to its parent process.
        return (-2);
    }

    close(fd);          /* we've read it all now */

    /*
     *  Now set the page table entries for the program text to be readable
     *  and executable, but not writable.
     */
    // >>>> For text_npg number of PTEs corresponding to the user text
    // >>>> pages, set each PTE's kprot to PROT_READ | PROT_EXEC.
    for (i = MEM_INVALID_PAGES; i < MEM_INVALID_PAGES + text_npg; i++) {
        region_0_pt[i].kprot = PROT_READ | PROT_EXEC;
    }

    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Zero out the bss
     */
    memset((void *)(MEM_INVALID_SIZE + li.text_size + li.data_size),
           '\0', li.bss_size);


    /*
     *  Set the entry point in the exception frame.
     */
    //>>>> Initialize pc for the current process to (void *)li.entry
    info->pc = (void *)li.entry;

    /*
     *  Now, finally, build the argument list on the new stack.
     */
    *cpp++ = (char *)argcount;      /* the first value at cpp is argc */
    cp2 = argbuf;
    for (i = 0; i < argcount; i++) {      /* copy each argument and set argv */
        *cpp++ = cp;
        strcpy(cp, cp2);
        cp += strlen(cp) + 1;
        cp2 += strlen(cp2) + 1;
    }
    free(argbuf);
    *cpp++ = NULL;  /* the last argv is a NULL pointer */
    *cpp++ = NULL;  /* a NULL pointer for an empty envp */
    *cpp++ = 0;     /* and terminate the auxiliary vector */

    /*
     *  Initialize all regs[] registers for the current process to 0,
     *  initialize the PSR for the current process also to 0.  This
     *  value for the PSR will make the process run in user mode,
     *  since this PSR value of 0 does not have the PSR_MODE bit set.
     */
    // >>>> Initialize regs[0] through regs[NUM_REGS-1] for the
    // >>>> current process to 0.
    // >>>> Initialize psr for the current process to 0.
    for (i = 0; i < NUM_REGS; i++) {
        info->regs[i] = 0;
    }
    info->psr = 0;

    return (0);
}
