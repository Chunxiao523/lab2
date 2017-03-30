
#include "help.h"
/*
 * keep tracking the location of the current break for the kernel
 */
void *kernel_cur_break;

/*
 * flag to indicate if you have yet enabled virtual memory
 * 0: not, 1: yes
 */
int vir_mem = 0;
/*
 * pid value
 */
int pid = 0;
/*
 * Page table for the region 1
 */
struct pte *kernel_page_table;
/*
 * Page table for the region 0
 */
struct pte *process_page_table;
/*
 * Page table for idle process
 */
struct  pte *idle_page_table;
/*
 * Data structure of process
 */
typedef struct pcb {
    SavedContext *ctx;
    int pid;
    pte * page_table;
    int child_num;
    int clock_ticks;
    struct pcb *parent;
    struct pcb *readynext;
    struct pcb *delaynext;
    struct proc_queue *status_queue;
    unsigned long brk;
} pcb;

pcb *cur_Proc;
pcb *idle;
pcb *init;
/*
 * Head of the delay queue
 */
pcb *delayQ;
/*
 * Head of the ready queue
 */
pcb *readyQ;

struct status_queue{
    int pid;
    int status;
};

/*
 * The table used to store the interrupts
 */
typedef void (*interrupt_handler)(ExceptionInfo *info);
/*
 * Linked list to store the free pages
 */
free_page *head;

int free_page_num = 0;

/*
define the terminals, which holds the read queue, write queue, readbuffer, writebuffer for each terms
*/
struct terminal
{
    pcb *readQ_head;
    pcb *readQ_tail;
    pcb *writeQ_head;
    pcb *writeQ_tail;
    char *readBuffer;
    int readed;
    char *writeBuffer;
    int char_num;
};

struct terminal terms[NUM_TERMINALS];
//terminal terms[NUM_TERMINALS];

void TrapKernel(ExceptionInfo *info);
void TrapClock(ExceptionInfo *info);
void TrapIllegal(ExceptionInfo *info);
void TrapMemory(ExceptionInfo *info);
void TrapMath(ExceptionInfo *info);
void TrapTTYReceive(ExceptionInfo *info);
void TrapTTYTransmit(ExceptionInfo *info);
unsigned long find_free_page();
void allocPageTable(pcb* p);
SavedContext *MyKernelSwitchFunc(SavedContext *ctxp, void *p1, void *p2);
SavedContext *clockSwitch(SavedContext *ctxp, void *p1, void *p2);
int MyGetPid();
void *va2pa(void *va);

/**
 * The procedure named KernelStart is automatically called by the bootstrap firmware in the computer
 * initialize your operating system kernel and then return. 
 * *info. a pointer to an initial ExceptionInfo structure
 * pmem_size total size of the physical memory
 * *org_brk gives the initial value of the kernel’s “break
 * **cmd_args.containing a pointer to each argument from the boot command line
 */
void KernelStart(ExceptionInfo *info, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
    unsigned int i;
    TracePrintf(1, "Kernel Start: KernelStart called with num physical pages: %d.\n", pmem_size/PAGESIZE);
    free_page_num = 0;
	kernel_cur_break = orig_brk;

	kernel_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);
	process_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);
    idle_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);

    readyQ = (pcb *)malloc(sizeof(pcb));
    delayQ = (pcb *)malloc(sizeof(pcb));
    readyQ->readynext = NULL;
    delayQ->delaynext = NULL;
	/*
	 * Initialize the interrupt table
	 * You need to initialize page table entries for Region 1 for the kernel's text, data, bss, and heap,
	 * and for Region 0 for the kernel's stack.
	 * All other PTEs should be marked invalid initially.
	 */
	interrupt_handler *interrupt_vector_table = (interrupt_handler *) malloc(TRAP_VECTOR_SIZE * sizeof(interrupt_handler));

	 interrupt_vector_table[TRAP_KERNEL] = TrapKernel;
	 interrupt_vector_table[TRAP_CLOCK] = TrapClock;
	 interrupt_vector_table[TRAP_ILLEGAL] = TrapIllegal;
	 interrupt_vector_table[TRAP_MEMORY] = TrapMemory;
	 interrupt_vector_table[TRAP_MATH] = TrapMath;
	 interrupt_vector_table[TRAP_TTY_RECEIVE] = TrapTTYReceive;
	 interrupt_vector_table[TRAP_TTY_TRANSMIT] = TrapTTYTransmit;

	 for (i=7; i<TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table[i] = NULL;
     }
	WriteRegister(REG_VECTOR_BASE, (RCS421RegVal)(interrupt_vector_table));
    TracePrintf(2, "Kernel Start: interrupt table initialized.\n");

    /* initialize the free phys pages list */
    head = (free_page*) malloc(sizeof(free_page));
	free_page *pointer = head;
    for(i = PMEM_BASE; i < PMEM_BASE + pmem_size; i += PAGESIZE) {
        pointer->next = (free_page*) malloc(sizeof(free_page));
        pointer = pointer->next;
        free_page_num++;
        pointer->phys_page_num = free_page_num;
    }

    pointer = head;
	free_page *t;
    while (pointer->next!=NULL) {
        if (pointer->next->phys_page_num >= (KERNEL_STACK_BASE>>PAGESHIFT) && pointer->next->phys_page_num<((unsigned long)kernel_cur_break>>PAGESHIFT)) {
            t = pointer->next;
            pointer->next = pointer->next->next;
            free_page_num --;
            free(t);
        }
        else pointer = pointer->next;
    }


	/*
     * Initialize the page table and page table register for region 1 and 0
     */
	TracePrintf(2, "Kernel Start: free physical address list initialized.\n");
	WriteRegister(REG_PTR1,(RCS421RegVal)(kernel_page_table));

	unsigned long addr;
    for (addr = VMEM_1_BASE; addr<UP_TO_PAGE((unsigned long)(&_etext)); addr+=PAGESIZE) {
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
        kernel_page_table[i].pfn = addr>>PAGESHIFT; //page frame number
        kernel_page_table[i].valid = 1;
        kernel_page_table[i].kprot = PROT_READ|PROT_EXEC;
        kernel_page_table[i].uprot = PROT_NONE;
    }

    for (; addr<UP_TO_PAGE((unsigned long)kernel_cur_break); addr += PAGESIZE) {
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
        kernel_page_table[i].pfn = addr>>PAGESHIFT;
        kernel_page_table[i].valid = 1;
        kernel_page_table[i].kprot = PROT_READ|PROT_WRITE;
        kernel_page_table[i].uprot = PROT_NONE;
    }

	for (; addr<VMEM_1_LIMIT; addr += PAGESIZE) {
		i = (addr-VMEM_1_BASE)>>PAGESHIFT;
		kernel_page_table[i].valid = 0;
	}
    TracePrintf(2, "Kernel Start: region 1 page table initialized.\n");
    TracePrintf(2, "Kernel Start: region 0 table address. %d\n", process_page_table);
    WriteRegister(REG_PTR0, (RCS421RegVal)(process_page_table));

    for (addr = VMEM_0_BASE; addr< KERNEL_STACK_BASE; addr += PAGESIZE) {
        i = (addr-VMEM_0_BASE)>>PAGESHIFT;
        process_page_table[i].valid = 0;
        idle_page_table[i].valid = 0;
    }
    for (addr = KERNEL_STACK_BASE; addr < VMEM_0_LIMIT; addr+= PAGESIZE) {
    	i = (addr - VMEM_0_BASE)>>PAGESHIFT; //VMEM_0_BASE = 0
    	process_page_table[i].pfn = addr>>PAGESHIFT;
        process_page_table[i].valid = 1;
        process_page_table[i].kprot = PROT_READ|PROT_WRITE;
        process_page_table[i].uprot = PROT_NONE;

        idle_page_table[i].pfn = addr>>PAGESHIFT;;
        idle_page_table[i].valid = 0;
        idle_page_table[i].kprot = PROT_NONE;
        idle_page_table[i].uprot = PROT_NONE;
    }

    TracePrintf(2, "Kernel Start: region 0 page table initialized.\n");


	/* enable the virtual memory subsystem */
	WriteRegister(REG_VM_ENABLE, 1);
	vir_mem = 1;
    TracePrintf(2, "Kernel Start: virtual memory enabled.\n");

	/*
	 * Create idle and init process
	 */
	idle = (pcb*)malloc(sizeof(pcb));
    idle->pid = pid;
    idle->page_table = idle_page_table;
	pid ++;
    idle->ctx=(SavedContext*)malloc(sizeof(SavedContext));
    TracePrintf(2, "Kernel Start: idle process pcb initialized.\n");

	init = (pcb *) malloc(sizeof(pcb));
	init->pid = pid;
    init->page_table = process_page_table;
	pid ++;
	init->ctx = (SavedContext *)malloc(sizeof(SavedContext));
	cur_Proc = init;

    LoadProgram("init",cmd_args,info, process_page_table);
    TracePrintf(2, "Kernel Start: init process pcb initialized.\n");

	ContextSwitch(MyKernelSwitchFunc, init->ctx, (void *) cur_Proc, (void *) idle);
    TracePrintf(2, "Kernel Start: Context Switch finished.\n");
    LoadProgram("idle",cmd_args,info, idle->page_table);
    cur_Proc = idle;
}
/**
 * SetKernelBrk
 */
int SetKernelBrk(void *addr) {
	if ((unsigned long *)addr >= VMEM_1_LIMIT || (unsigned long *)addr < VMEM_1_BASE) return -1;
	if (vir_mem == 0) {
		kernel_cur_break = addr;
	} else {
		// first allocate free memory of size *addr - *kernel_brk from list of free phisical memory
		// second map these new free phisical memory to page_table_1
		// then grow kernel_brk to addr frame by frame
		if(addr > kernel_cur_break) {
			TracePrintf(2, "Set kernel brk: addr > kernel_cur_break \n");
			int i;
            if ( DOWN_TO_PAGE(*(unsigned long *)addr) - UP_TO_PAGE(kernel_cur_break) > PAGESIZE*free_page_num) {
                TracePrintf(2, "Set Kernel brk: add invalid\n");
                return -1;
            }

			/* Given a virtual page number, assign a physical page to its corresponding pte entry */
			for(i = (UP_TO_PAGE(kernel_cur_break) - VMEM_1_BASE)>>PAGESHIFT; i < (UP_TO_PAGE(addr) - VMEM_1_BASE)>>PAGESHIFT; i++) {
                kernel_page_table[i].pfn = find_free_page();
                kernel_page_table[i].valid = 1;
                kernel_page_table[i].kprot = PROT_READ|PROT_WRITE;
                kernel_page_table[i].uprot = PROT_NONE;
			}
            kernel_cur_break = UP_TO_PAGE(addr);
		} else {
            TracePrintf(2, "Set kernel brk: addr <= kernel_cur_break, This is not supposed to happen \n");
            return -1;
        }
	}
	return 0;
}
/**
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
				(*info).regs[0] = MyGetPid();
				break;
			case YALNIX_BRK:
				(*info).regs[0] = NULL;
				break;
			case YALNIX_DELAY:
				(*info).regs[0] = MyDelay((int)info->regs[1]);
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
    TracePrintf(2, "Kernel call: Trap clock\n");
    pcb *temp = delayQ;
    while (temp->delaynext != NULL){
        temp->delaynext->clock_ticks --;
        if(temp->clock_ticks == 0) {
            //add to ready queue
            add_readyQ(temp->delaynext);
            temp -> delaynext = temp->delaynext->delaynext;
        }else {
            temp = temp->delaynext;
        }
    }
    ContextSwitch(clockSwitch, cur_Proc->ctx, cur_Proc, readyQ);
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

// when terminal has typing return, hardware produce a trapttyreceive to kernel
// this handler is to read newline into readbuffer located in region1
void TrapTTYReceive(ExceptionInfo *info) {
    //use TtyReceive to write line into buf in region 1, which return the acutual char
    int tty_id = info->code;
    int char_num;
    char_num = TtyReceive(tty_id, terms[tty_id].readBuffer + terms[tty_id].readed, TERMINAL_MAX_LINE);
    terms[tty_id].readed += char_num;
    // need context switch here?

//    int tty_id = info->code;
//    int char_num;
//    char_num = TtyReceive(tty_id, buf, TERMINAL_MAX_LINE);
//
//    if (terms[tty_id].readQueue!= NULL) {
//    //    ContextSwitch(, cur_Proc->ctx, cur_Proc, ready_queue);
//    }

}

void TrapTTYTransmit(ExceptionInfo *info) {
    int tty_id = info->code;
 //   ContextSwitch();
}

/************ Context switch function **********/
/**
 * Context switch between these two processes
 * p1 and p2 are passed to ContextSwitch will be passed unmodified to MySwitchFunc.
 * p1 is to be switched out of region 0 and p2 is to be switched into region 0
 * You should use them to point to the current process's PCB and to the PCB of the new process
 * to be context switch between these two processes
 *
 */
SavedContext *MyKernelSwitchFunc(SavedContext *ctxp, void *p1, void *p2) {
    TracePrintf(2, "Context Switch: ***************** Begining Context Switch!!!*****************\n");

    struct pcb *pcb_ptr2 = (struct pcb *)p2;
    struct pcb *pcb_ptr1 = (struct pcb *)p1;

    struct pte *p1_pt = pcb_ptr1->page_table;
    struct pte *p2_pt = pcb_ptr2->page_table;

    int i;
    unsigned long addr;
    TracePrintf(2, "Context Switch: Process 1 and Process 2 page table initialized, begin loop\n");

   for(i = 0; i <KERNEL_STACK_PAGES; i ++) {
       addr = KERNEL_STACK_BASE + i * PAGESIZE + VMEM_0_BASE;
       TracePrintf(2, "Context Switch: Working with %d kernel stack page\n", addr  >> PAGESHIFT);

       unsigned long temp;
       unsigned long p2_pfn = find_free_page(); //physical page number to store process 2
       TracePrintf(2, "Context Switch: physical address %d \n", p2_pfn);
       for (temp = MEM_INVALID_PAGES; temp < KERNEL_STACK_BASE>>PAGESHIFT; temp++) {
           /*
            * Find the first invalid page in p1_pt, as a buffer to help copy the kernel stack content
            */
           if (p1_pt[temp].valid == 0) {
               TracePrintf(2, "Context Switch: Copying...   %d\n", temp );
               p1_pt[temp].valid = 1;
               p1_pt[temp].uprot = PROT_READ | PROT_EXEC;
               p1_pt[temp].kprot = PROT_READ | PROT_WRITE;
               p1_pt[temp].pfn = p2_pfn;

               void *temp_addr = (void *)((temp * PAGESIZE) + VMEM_0_BASE); //virtual address to the buffer pte

               WriteRegister(REG_TLB_FLUSH, (RCS421RegVal)temp_addr);

               memcpy(temp_addr, (void *)addr, PAGESIZE); // copy kernel stack page to the new physical memory
               TracePrintf(2, "Context Switch: Copied!\n");

               p1_pt[temp].valid = 0; //delete the pointer from the buffer page to the physical address
               WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) temp_addr);

               // give the pfn from the temp memory to process 2's page table.
               p2_pt[((addr - VMEM_0_BASE) >> PAGESHIFT)].pfn = p2_pfn;
               p2_pt[((addr - VMEM_0_BASE) >> PAGESHIFT)].valid = 1;
               p2_pt[((addr - VMEM_0_BASE) >> PAGESHIFT)].kprot = PROT_READ|PROT_WRITE;
               p2_pt[((addr - VMEM_0_BASE) >> PAGESHIFT)].uprot = PROT_NONE;
               break;
           }
       }

    }
  //  p2_pt[508].valid = 1;
    WriteRegister(REG_PTR0, (RCS421RegVal)p2_pt); // Set the register for region 0
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0); // flush
    TracePrintf(2, "Context Switch: finish context switch\n");

    // update globale variables, and load idle
    cur_Proc = (pcb *)pcb_ptr2;
    memcpy(((pcb *)pcb_ptr2)->ctx, ((pcb *)pcb_ptr1)->ctx, sizeof(SavedContext));
	return pcb_ptr2->ctx;
}
SavedContext *delayContextSwitch(SavedContext *ctxp, void *p1, void *p2){
    if(readyQ == NULL) {
        WriteRegister(REG_PTR0, (RCS421RegVal)idle->page_table); // Set the register for region 0
        WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
        cur_Proc = idle;
    } else {
        WriteRegister(REG_PTR0, (RCS421RegVal)((pcb *)p2)->page_table); // Set the register for region 0
        WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
        cur_Proc = ((pcb *)p2);
    }
    return cur_Proc->ctx;
}
SavedContext *clockSwitch(SavedContext *ctxp, void *p1, void *p2) {
    TracePrintf(2, "Context Switch: Context switch undering a Clock interrupt handler \n");
    if (p2 != NULL) {
        WriteRegister(REG_PTR0, (RCS421RegVal)((pcb *) p2)->page_table); // Set the register for region 0
        WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);
        cur_Proc = ((pcb *)p2);
    }
    return cur_Proc->ctx;
}
// copy page table, kernel stack and ctxp from p1 to p2
SavedContext *forkSwitch(SavedContext *ctxp, void *p1, void *p2) {
    unsigned long i;
    for (i=0;i<PAGE_TABLE_LEN;i++) {

    }
}

/*************** Kernel Call ***************/
/**
 * Get pid kernel call
 */
int MyGetPid() {
    if (cur_Proc != NULL) {
        return cur_Proc->pid;
    } else {
        return -1;
    }
}
/**
 * Delay kernel call
 */
int MyDelay(int clock_ticks) {
    int i;
    if(clock_ticks<0)
        return ERROR;
     cur_Proc->clock_ticks=clock_ticks;
    if(clock_ticks>0){
        ContextSwitch(delayContextSwitch,cur_Proc->ctx,cur_Proc,readyQ);
        add_delayQ(cur_Proc);
    }
    return 0;
}

/*
set the loweast location not used by the program
the actual break sould be rounded up to the pagesize
*/
int MyBrk(void *addr) {
    // invalid assign
//    if (addr == NULL)
//        return ERROR;
//
//    unsigned long addr_pgn = UP_TO_PAGE(addr) >> PAGESHIFT;
//    unsigned long brk_pgn = UP_TO_PAGE(cur_Proc->brk) >> PAGESHIFT;
//    unsigned long i;
//
//    if (addr_pgn >= user_stack_bott()-1)
//        return ERROR;
//
//    // allocate
//    if (addr_pgn >= brk_pgn) {
//        if (addr_pgn - brk_pgn>free_page_num)
//            return ERROR;
//
//        for (i=MEM_INVALID_PAGES;i<addr_pgn;i++) {
//            if (cur_Proc->page_table[i].valid == 0) {
//                cur_Proc->page_table[i].valid = 1;
//                cur_Proc->page_table[i].valid=1;
//                cur_Proc->page_table[i].uprot=PROT_READ|PROT_WRITE;
//                cur_Proc->page_table[i].kprot=PROT_READ|PROT_WRITE;
//                cur_Proc->page_table[i].pfn=find_free_page();
//            }
//        }
//    } else {
//        // deallocate
//        for (i=brk_pgn;i>=addr_pgn;i--) {
//            if (cur_Proc->page_table[i].valid == 1) {
//                cur_Proc->page_table[i].valid = 0;
//                free_used_page(cur_Proc->page_table[i]);
//            }
//        }
//    }
//    cur_Proc->brk = (unsigned long)addr;
    return 0;
}

/* input args: nond
 * return val: process ID for parent process, 0 for child process
 * child process's address is a copy of parent process's address space, the copy should include
 * neccessary information from parent process's pcb such as ctx*/
int MyFork(void) {
	int child_pid;
	unsigned long i;
    pcb* parent;
    parent = cur_Proc;
    pcb* child;

    // find out the used page count for the parent process
    int used_pgn_count = 0;
    int count;
    for (count = 0; count < PAGE_TABLE_LEN; count++) {
        if (parent->page_table[count].valid) {
            used_pgn_count++;
        }
    }

    // check if there is enough physical mem for the child
	if (used_pgn_count > free_page_num) {
		return -1;
		TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
	} else {
        // create a new pcb, savedcontext, and a new page table for child
        child = (pcb*) malloc(sizeof(pcb));
        child->ctx = (SavedContext*) malloc(sizeof(SavedContext));
        allocPageTable(child);
        // copy pcb, savedcontext, pagetable from parent to child
        child->pid=pid++;
        child->child_num = 0;
        child->clock_ticks = 0;
        child->parent = cur_Proc;
        child->brk = parent->brk;
        // why need readynext in the pcb?

        // copy content of parent to child: savedcontext and page table in the context switch
       // ContextSwitch(switch_fork,parent->ctx, (void*) parent, (void*) child);
        // run the child 
        cur_Proc = child;
        return 0;
        TracePrintf(0,"fork : else");
    }

   // ContextSwitch(parent->ctx,parent,child);
    
}

/*
Replace the current process with process stored in filename
if failure, return ERROR
*/
int MyExec(char *filename, char **argvec, ExceptionInfo *info, struct pte *process_page_table) {
    int status;
    status = LoadProgram(filename, argvec, info, process_page_table);
    if (status == -1)
        return ERROR;
    // if (status == -2)
        // MyExit(ERROR);
    return 0;
	TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

/*
kernel call for terminalling a process
para: the status of this process
if a child is terminate, it report status to its wait parent
if a parent is terminate, its child's parent become null
when a process exit, its resourses should be freed
*/
void MyExit(int status){

    struct pcb *next_Proc;

    // // if it is idle, idle would never exit
    // if (cur_Proc->pid == 0)
    //     return

    // // if it is init
    // if (cur_Proc->pid == 1) 
    //     Halt();

    // // find the next process to run
    // cur_Proc = next_Proc;
    // next_Proc = 


 return ;
	TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

/*

Collect the process ID and exit status returned by a child process of the calling program. When a child process Exits, 
its exit status information is added to a FIFO queue of child processes not yet collected by its specific parent. After the Wait 
call, this child process information is removed from the queue. If the calling process has no remaining child processes (exited or 
running), ERROR is returned instead as the result of the Wait call and the integer pointed to by status_ptr is not modified. Otherwise, 
if there are no exited child processes waiting for collection by this calling process, the calling process is blocked until its next child 
calls exits or is terminated by the kernel (if a process is terminated by the kernel, its exit status should appear to its parent as ERROR). 
On success, the Wait call returns the process ID of the child process and that child’s exit status is copied to the integer pointed to 
by the status_ptr argument. On any error, this call instead returns ERROR.
*/
int MyWait(int *status_ptr) {

    int return_pid;
return 0;
	TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

/*Read the next line of input (or a portion of it) from terminal tty_id, copying the bytes of input into the buffer referenced by buf. 
The maximum length of the line to be returned is given by len. A value of 0 for len is not in itself an error, as this simply means to 
read “nothing” from the terminal. The line returned in the buffer is not null-terminated.
The calling process is blocked until a line of input is available to be returned. If the length of the next available input line is longer 
than len bytes, only the first len bytes of the line are copied to the calling process’s buffer, and the remaining bytes of the line are
 saved by the kernel for the next TtyRead (by this or another process) for this terminal. If the length of the next available input line 
 is shorter than len bytes, only as many bytes are copied to the calling process’s buffer as are available in the input line. On success, 
 the number of bytes actually copied into the calling process’s buffer is returned; in case of any error, the value ERROR is returned.
 */

int TtyRead(int tty_id, void *buf, int len) {
    if (len < 0 || buf == NULL)
        return ERROR;
    if (len == 0)
        return 0;
    // while (terms[tty_id].char_num == 0) blocked;
    if (len <= terms[tty_id].char_num) {
        memcpy(buf,terms[tty_id].readBuffer, len);
        return len;
    }
    else {
        memcpy(buf, terms[tty_id].readBuffer, terms[tty_id].char_num);
        return terms[tty_id].char_num;
    }
	return 0;
	TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

/*Write the contents of the buffer referenced by buf to the terminal tty_id. The length of the buffer in bytes is given by len

*/
int TtyWrite(int tty_id, void *buf, int len) {
	return 0;
	TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

// used to allocate physical memory for page table after valid virtual memory
unsigned long pa_next_table;
int half = 0; // 1 is not half

void allocPageTable(pcb* p) {
    if (half == 1) {
        p->page_table = pa_next_table;
        pa_next_table += PAGESIZE/2;
        half = 0;
    } else {
        pa_next_table = find_free_page();
        p->page_table = pa_next_table;
        pa_next_table += PAGESIZE;
        half = 1;
    }
}

//void enqueue(struct proc_queue *queue, pcb *p) {
//    if (queue->head == NULL)
//        queue->head = p;
//    else
//        queue->tail->next = p;
//    queue->tail = p;
//    p->next = NULL;
//}
//
//pcb *dequeue(struct proc_queue *queue) {
//    pcb *nextNode;
//    if (queue->head == NULL)
//        return NULL;
//    nextNode = queue->head;
//    queue->head = queue->head->next;
//    nextNode->next = NULL;
//    return nextNode;
//}

void add_readyQ(pcb *p) {
    pcb *temp = readyQ;
    while(temp != NULL) {
        temp = temp->readynext;
    }
    temp->readynext = p;
    p->readynext = NULL;
}
void add_delayQ(pcb *p) {
    // Add Current Process to the tail of delayQ
    pcb *temp = delayQ;
    while(temp->delaynext != NULL) {
        temp = temp->delaynext;
    }
    cur_Proc->delaynext = temp->delaynext;
    temp->delaynext = cur_Proc;
}


// find out the bottom of the user stack
//unsigned long user_stack_bott(void) {
//    unsigned long bottom;
////    bottom = KERNEL_STACK_BASE >> PAGESHIFT - 1;
////    while (process_page_table[bottom].valid)
////        bottom--;
//    return bottom;
//}

/**
 * Return a free page pfn from the linked list
 */
unsigned long find_free_page() {
    TracePrintf(2, "Find free page: finding...\n");
        if (head->next==NULL) {
            TracePrintf(2, "Find Free Page: list is empty \n");
            return 0;
        }
        free_page *tmp = head->next;
        head->next = tmp->next;
        free_page_num--;
        //unsigned long ret = tmp->phys_addr_pgn;
        unsigned long ret = tmp->phys_page_num;
//      free(tmp);
//      tmp = NULL;
        return ret;
}

int free_used_page(pte *p) {
    if (p == NULL)
        return ERROR;
    // pfn to address ?= pfn * pagesize;
    free((p->pfn) * PAGESIZE);
    TracePrintf(0, "free the page number address %d", (p->pfn) * PAGESIZE);
    free_page *tmp = (free_page*) malloc(sizeof(free_page));
    tmp->next = head->next;
    head->next = tmp;
    return 1;
}

/**
 * Function to map virtual address to physical address
 * (used in context switch)
 * @param va virtual address
 * @return physical address
 */
void *va2pa(void *va) {
    if (DOWN_TO_PAGE(va) >= VMEM_1_BASE) {
        TracePrintf(2, "Va to Pa: Virtual address in region 1\n");
        return (void *)((long)kernel_page_table[((long)DOWN_TO_PAGE(va) - VMEM_1_BASE) >> PAGESHIFT].pfn*PAGESIZE + ((long)va & PAGEOFFSET)) ;
    } else {
        TracePrintf(2, "Va to Pa: Virtual address in region 0\n");
        return (void *)((long)cur_Proc->page_table[((long)DOWN_TO_PAGE(va) - VMEM_0_BASE) >> PAGESHIFT].pfn);
    }
}

