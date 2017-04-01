
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
stack buffer for context switch
*/
char kernel_stack_buff[PAGESIZE*KERNEL_STACK_PAGES];


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
struct  pte *init_page_table;
/*
 * Data structure of process
 */
typedef struct pcb {
    SavedContext *ctx;
    int pid;
    pte * page_table;
    int clock_ticks;
    unsigned long brk;
    struct pcb *parent;
    struct pcb *readynext;
    struct pcb *delaynext;
    struct pcb *waitnext;
    struct pcb *delaypre;
    struct pcb *readypre;
    struct ChildStatus *statusQ;
    struct ChildNode *childQ;

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

/*
 * FIFO wait queue
 */
pcb *waitQ;

/*
 * child of a process which store its pid and status
 */
typedef struct ChildStatus{
    int pid;
    int status;
    struct ChildStatus *next;
} ChildStatus;

/*
 * child of a process which store its pid and status
 */
typedef struct ChildNode{
    struct pcb *node;
    struct ChildNode *next;
} ChildNode;


/*
 * The table used to store the interrupts
 */
typedef void (*interrupt_handler)(ExceptionInfo *info);
/*
 * Linked list to store the free pages
 */
free_page *head;
free_page *newpage;

int free_page_num;
int entry_number;
/*
define the terminals, which holds the read queue, write queue, readbuffer, writebuffer for each terms
*/
struct terminal
{
    char *readBuff[256];
    int buf_ch_cnt;
    char *writeBuffer;
    struct ReadNode *readQ;
};

/*
 * child of a process which store its pid and status
 */
typedef struct ReadNode{
    struct pcb *node;
    struct ReadNode *next;
} ReadNode;

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
unsigned long user_stack_bott();
unsigned long buf_region1();
void MyExit(int status);
void delete_child(pcb *p);
void add_statusQ(int status);
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
    init_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);

    readyQ = (pcb *)malloc(sizeof(pcb));
    delayQ = (pcb *)malloc(sizeof(pcb));

    readyQ = NULL;
    delayQ = NULL;
    // readyQ->readynext = NULL;
    // delayQ->delaynext = NULL;
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
        pointer->next = (free_page*)malloc(sizeof(free_page));
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

    /* initialize the terminals*/
    /* initialize the terminal */

    for(i=0;i<NUM_TERMINALS;i++){
        terms[i].buf_ch_cnt=0;
        terms[i].readQ=NULL;
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
        init_page_table[i].valid = 0;
    }
    for (addr = KERNEL_STACK_BASE; addr < VMEM_0_LIMIT; addr+= PAGESIZE) {
        i = (addr - VMEM_0_BASE)>>PAGESHIFT; //VMEM_0_BASE = 0
        process_page_table[i].pfn = addr>>PAGESHIFT;
        process_page_table[i].valid = 1;
        process_page_table[i].kprot = PROT_READ|PROT_WRITE;
        process_page_table[i].uprot = PROT_NONE;

        init_page_table[i].pfn = addr>>PAGESHIFT;;
        init_page_table[i].valid = 0;
        init_page_table[i].kprot = PROT_NONE;
        init_page_table[i].uprot = PROT_NONE;
    }

    TracePrintf(2, "Kernel Start: region 0 page table initialized.\n");


    /* enable the virtual memory subsystem */
    WriteRegister(REG_VM_ENABLE, 1);
    vir_mem = 1;
    TracePrintf(2, "Kernel Start: virtual memory enabled.\n");
   //if(cmd_args[0] == NULL) {
    /*
	 * Create idle and init process
	 */
        idle = (pcb*)malloc(sizeof(pcb));
        idle->pid = pid;
        idle->page_table = process_page_table;
        pid ++;
        idle->ctx=(SavedContext*)malloc(sizeof(SavedContext));
        TracePrintf(2, "Kernel Start: idle process pcb initialized.\n");

        init = (pcb *) malloc(sizeof(pcb));
        init->pid = pid;
        init->page_table = init_page_table;
        pid ++;
        init->ctx = (SavedContext *)malloc(sizeof(SavedContext));


        LoadProgram("idle",cmd_args,info, process_page_table);
        cur_Proc = idle;
        TracePrintf(2, "Kernel Start: idle process pcb initialized.\n");

        ContextSwitch(MyKernelSwitchFunc, cur_Proc->ctx, (void *) cur_Proc, (void *) init);

        if(cur_Proc->pid==0) //current running process is idle
            LoadProgram("idle",cmd_args, info, process_page_table);
        else if(cur_Proc->pid==1) {
            if (cmd_args==NULL || cmd_args[0]==NULL) LoadProgram("init",cmd_args,info, init_page_table);
            else {
                LoadProgram(cmd_args[0], cmd_args, info, init_page_table);
                fprintf(stderr,  "Kernel Start: running your process now.\n");
            }
        }
}
/**
 * SetKernelBrk
 */
int SetKernelBrk(void *addr) {
    if ((unsigned long *)addr >= VMEM_1_LIMIT || (unsigned long *)addr < VMEM_1_BASE) {
        TracePrintf(2, "Set Kernel brk: add invalid!\n");
        return -1;
    }
    if (vir_mem == 0) {
        kernel_cur_break = addr;
    } else {
        // first allocate free memory of size *addr - *kernel_brk from list of free phisical memory
        // second map these new free phisical memory to page_table_1
        // then grow kernel_brk to addr frame by frame
        if(addr > kernel_cur_break) {
            TracePrintf(2, "Set kernel brk: addr > kernel_cur_break \n");
            int i;
            if ( UP_TO_PAGE(addr) - UP_TO_PAGE(kernel_cur_break) > PAGESIZE*free_page_num) {
                TracePrintf(2, "Set Kernel brk: Not enough pages\n");
                return -1;
            }
            TracePrintf(2, "Set Kernel brk: working now!...\n");
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
            (*info).regs[0] = MyFork();
            break;
        case YALNIX_EXEC:
            (*info).regs[0] = MyExec(info, (char *)(info->regs[1]), (char **)(info->regs[2]));
            break;
        case YALNIX_EXIT:
            MyExit((int)info->regs[1]);
            break;
        case YALNIX_WAIT:
            (*info).regs[0] = MyWait((int)info->regs[1]);
            break;
        case YALNIX_GETPID:
            (*info).regs[0] = MyGetPid();
            break;
        case YALNIX_BRK:
            (*info).regs[0] = MyBrk((void *)info->regs[1]);
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

    while (temp != NULL){
     //   TracePrintf(2, "Kernel call: delete the delay queue clock\n");
        temp->clock_ticks --;
        TracePrintf(2, "Kernel call: Trap clock, delayQ clock ticks changes to %d\n", temp->clock_ticks);
        if(temp->clock_ticks == 0) {
            //add to ready queue
            TracePrintf(2, "Kernel call: Trap clock, delayQ clock ticks changes to %d\n", temp->clock_ticks);
            add_readyQ(temp);
            if (temp->delaypre != NULL) {
                temp -> delaypre -> delaynext = temp->delaynext;
            }
        }
        temp = temp->delaynext;
    }

    if (readyQ != NULL) {
        TracePrintf(2, "Kernel call: Trap clock Context switch!\n");
        ContextSwitch(clockSwitch, cur_Proc->ctx, cur_Proc, readyQ);
    }
    TracePrintf(2, "Kernel call: Finish one clock\n");
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
// int TtyReceive(int term_id, void *buf, int len)
// When the user completes an input line on a terminal, the RCS 421 hardware terminal controller will generate a TRAP_TTY_RECEIVE interrupt
// for this terminal

// The terminal number of the terminal generating the interrupt will be made available to the kernel’s interrupt handler for this type of
// interrupt. In the interrupt handler, the kernel should execute a TtyReceive operation for this terminal, in order to retrieve
// the new input line from the hardware.

// The new input line is copied from the hardware for terminal term_id into the kernel buffer at virtual address buf,
//  for maximum length to copy of len bytes. The value of len must be equal to TERMINAL_MAX_LINE bytes,
// The buffer must be in the kernel’s virtual memory (i.e., it must be entirely within virtual memory Region 1).
// After each TRAP_TTY_RECEIVE interrupt, the kernel must do a TtyReceive and save the new input line in a buffer inside the kernel,
// e.g., until a user process requests the next line from the terminal by executing
// a kernel call to read from this device.

// The actual length of the new input line, including the newline (’\n’), is returned as the return value of TtyReceive. Thus when a blank line
// is typed, TtyReceive will return a 1, since the blank line is terminated by a newline character. When an end of file character (control-D)
// is typed, TtyReceive returns 0 for this line. End of file behaves just like any other line of input, however. In particular, you can continue
// to read more lines after an end of file. The data copied into your buffer by TtyReceive is not terminated with a null character (as would be
// typical for a string in C); to determine the end of the characters returned in the buffer, you must use the length returned by TtyReceive.

// NOW
void TrapTTYReceive(ExceptionInfo *info) {
    //use TtyReceive to write line into buf in region 1, which return the acutual char
    int term_id = info->code;
    int received_cnt;
    received_cnt = TtyReceive(term_id, terms[term_id].readBuff + terms[term_id].buf_ch_cnt, TERMINAL_MAX_LINE);
    terms[term_id].buf_ch_cnt += received_cnt;
}

void TrapTTYTransmit(ExceptionInfo *info) {
    int term_id = info->code;
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
    TracePrintf(0,"forkSwitch is called, ctx is %d \n", ctxp);
    unsigned long i, j;
    struct pcb* parent = (struct pcb*) p1;
    struct pcb* child = (struct pcb*)p2;
    struct pte* pt1 = parent->page_table;
    struct pte* pt2 = child->page_table;

    for (i = 0; i < PAGE_TABLE_LEN; i ++) {
        /*
         * Find the first invalid page in kernel page table, as a buffer to help copy
         */
        if(pt1[i].valid == 1) {
        TracePrintf(2, "Working on %d\n", i);
            for (j = 0; j < PAGE_TABLE_LEN; j++) {
                if (kernel_page_table[j].valid==0) {
                    entry_number = j;
                    unsigned long p2_pfn = find_free_page();

                    kernel_page_table[entry_number].valid = 1;
                    kernel_page_table[entry_number].uprot = PROT_NONE;
                    kernel_page_table[entry_number].kprot = PROT_READ | PROT_WRITE;
                    kernel_page_table[entry_number].pfn = p2_pfn;

                    void *vaddr_entry = (void*) (long) ((entry_number * PAGESIZE) + VMEM_1_BASE);

                    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) vaddr_entry);
                    //TracePrintf(2, "Set the register %d\n", j);
                    unsigned long addr = i * PAGESIZE + VMEM_0_BASE;
                    memcpy(vaddr_entry, (void *)addr, PAGESIZE);

                    kernel_page_table[entry_number].valid = 0; //delete the pointer from the buffer page to the physical address
                    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) vaddr_entry);

                    // give the pfn from the temp memory to process 2's page table.
                    pt2[i].pfn = p2_pfn;
                    pt2[i].valid = 1;
                    pt2[i].kprot = PROT_READ | PROT_WRITE;
                    if (i>=PAGE_TABLE_LEN-KERNEL_STACK_PAGES) pt2[i].uprot=PROT_NONE;
                    else pt2[i].uprot=PROT_READ | PROT_WRITE;
                    break;
                }
            }
        }
    }
    free_used_page(kernel_page_table[entry_number]);
    WriteRegister(REG_PTR0, (RCS421RegVal)va2pa((void *)pt2));
    WriteRegister(REG_TLB_FLUSH,TLB_FLUSH_0);
    memcpy(((pcb *)p2)->ctx, ctxp, sizeof(SavedContext));
    cur_Proc = child;
    add_readyQ(parent);
    return ((pcb *)p2)->ctx;
}

SavedContext *exitContextSwitch(SavedContext *ctxp, void *p1, void *p2){
    unsigned long i;
    struct pte *pt1 = ((pcb*)p1)->page_table;
    // free all the physical mem frame of p1
    for (i = 0; i < PAGE_TABLE_LEN; i++) {
        if (pt1[i].valid) {
            free_used_page(pt1[i]);
        }
    }
    // free its pcb content

    // free(p1->ctx);

    // free its status queue
    //
    // switch to the next process in the readyQ
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

//
// SavedContext *waitSwitch(SavedContext *ctxp, void *p1, void *p2) {
//     unsigned long i;
//     // save the context to ctxp
//     // return to the new context
//     pte* pt1 = ->page_table;
//     pte* pt2 = ->page_table;

// }
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
    if(clock_ticks<0 || clock_ticks == NULL)
        return ERROR;
    cur_Proc->clock_ticks=clock_ticks;
    if(clock_ticks>0){
        add_delayQ(cur_Proc);
        ContextSwitch(delayContextSwitch,cur_Proc->ctx,cur_Proc,readyQ);
    }
    return 0;
}

/*
set the lowest location not used by the program
the actual break should be rounded up to the pagesize
*/
int MyBrk(void *addr) {
    if (addr == NULL)
        return ERROR;

    unsigned long addr_pgn = UP_TO_PAGE(addr) >> PAGESHIFT;
    unsigned long brk_pgn = UP_TO_PAGE(cur_Proc->brk) >> PAGESHIFT;
    unsigned long i;

    if (addr_pgn >= user_stack_bott()-1)
        return ERROR;

    // allocate
    if (addr_pgn >= brk_pgn) {
        if (addr_pgn - brk_pgn>free_page_num)
            return ERROR;

        for (i=MEM_INVALID_PAGES;i<addr_pgn;i++) {
            if (cur_Proc->page_table[i].valid == 0) {
                cur_Proc->page_table[i].valid = 1;
                cur_Proc->page_table[i].uprot=PROT_READ|PROT_WRITE;
                cur_Proc->page_table[i].kprot=PROT_READ|PROT_WRITE;
                cur_Proc->page_table[i].pfn=find_free_page();
            }
        }
    } else {
        // deallocate
        for (i=brk_pgn;i>=addr_pgn;i--) {
            if (cur_Proc->page_table[i].valid == 1) {
                cur_Proc->page_table[i].valid = 0;
                free_used_page(cur_Proc->page_table[i]);
            }
        }
    }
    cur_Proc->brk = (unsigned long)addr;
    return 0;
}


/* input args: nond
 * return val: process ID for parent process, 0 for child process
 * child process's address is a copy of parent process's address space, the copy should include
 * neccessary information from parent process's pcb such as ctx*/
int MyFork(){
    TracePrintf(0, "fork is called\n");
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
    }

    // create a new pcb, savedcontext, and a new page table for child
    child = (pcb*) malloc(sizeof(pcb));
    child->ctx = (SavedContext*) malloc(sizeof(SavedContext));
    allocPageTable(child);
    // init the child's pcb
    child->pid=pid++;
    child->clock_ticks = 0;
    child->parent = cur_Proc;
    child->brk = parent->brk;
    child->childQ = NULL;
    child->statusQ = NULL;

    TracePrintf(0, "come to ContextSwitch\n");
    // copy the context, page table, page mem to the child and change to the child process, put the parent into the ready queue
    ContextSwitch(forkSwitch, parent->ctx, parent, child);
    if (cur_Proc->pid == parent->pid) {
        return child_pid;
    } else {
        return 0;
    }
}

/*
Replace the current process with process stored in filename
if failure, return ERROR
*/
int MyExec(ExceptionInfo *info, char *filename, char **argvec) {
    TracePrintf(0,"Kernel Call: EXEC called! .\n", filename);
    int status;
    status = LoadProgram(filename, argvec, info, process_page_table);
    if (status == -1)
        return ERROR;
    // if (status == -2)
    // MyExit(ERROR);
    TracePrintf(0,"Kernel Call: EXEC load %c successfully.\n", filename);
    return 0;
//
}

/*
When a process exits or is terminated by the kernel, all resources used by the calling process 
are freed, except for the saved status inform
tion (if the process is not an orphan). The Exit kernel call can never return.
kernel call for terminalling a process
return status to its parent
para: the status of this process
if a child is terminate, it report status to its wait parent
if a parent is terminate, its child's parent become null
when a process exit, its resourses should be freed
*/
void MyExit(int status){
    // if it is init or idle
    if(cur_Proc->pid==0||cur_Proc->pid==1){
        Halt();
    }


    // if it is parent, child delete parent
    if (cur_Proc->childQ != NULL) {
        ChildNode *tmp = cur_Proc->childQ;
        while(tmp != NULL) {
            tmp->node->parent = NULL;
            tmp = tmp->next;
        }
        TracePrintf(0, "MyExit: exit process has children\n");
    }

    // if p has a parent 
    // report status to its parent
    // delete itself from childQ of its parent, check if the parent should be assigned to the readyQ
    if (cur_Proc->parent != NULL) {
        TracePrintf(0, "myexit: exit process has parent\n");
        add_statusQ(cur_Proc);
        TracePrintf(0, "report status to its parent\n");
        delete_child(cur_Proc);
        TracePrintf(0, "myexit: delete_child");

        if (cur_Proc->parent->childQ == NULL) {
            add_readyQ(cur_Proc->parent);
            TracePrintf(0, "myexit: parent it put to readyqueue");
        }
    }
   // ContextSwitch(exitContextSwitch, cur_Proc->ctx, cur_Proc, readyQ);
    return 0;
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
     pcb *tmp = cur_Proc;
     // if calling process have no child, return ERROR
     if (cur_Proc->childQ == NULL)
         return ERROR;
     // if child status queue is empty, block the calling process, return until one child is exit or terminated
     if (cur_Proc->statusQ == NULL) {
        // ContextSwitch(delayContextSwitch(), cur_Proc->ctx,cur_Proc,get_readyQ());
         add_waitQ(tmp);
         return ERROR;
     }
     return_pid = tmp->statusQ->pid;
     *status_ptr = tmp->statusQ->status;

     return return_pid;
 }

/*Read the next line of input (or a portion of it) from terminal term_id, copying the bytes of input into the buffer referenced by buf.
The maximum length of the line to be returned is given by len. A value of 0 for len is not in itself an error, as this simply means to
read “nothing” from the terminal. The line returned in the buffer is not null-terminated.
The calling process is blocked until a line of input is available to be returned. If the length of the next available input line is longer
than len bytes, only the first len bytes of the line are copied to the calling process’s buffer, and the remaining bytes of the line are
 saved by the kernel for the next TtyRead (by this or another process) for this terminal. If the length of the next available input line
 is shorter than len bytes, only as many bytes are copied to the calling process’s buffer as are available in the input line. On success,
 the number of bytes actually copied into the calling process’s buffer is returned; in case of any error, the value ERROR is returned.
 */

int TtyRead(int term_id, void *buf, int len) {
    // if (len < 0 || buf == NULL)
    //     return ERROR;
    // if (len == 0)
    //     return 0;
    // // while (terms[term_id].char_num == 0) blocked;
    // if (len <= terms[term_id].char_num) {
    //     memcpy(buf,terms[term_id].readBuffer, len);
    //     return len;
    // }
    // else {
    //     memcpy(buf, terms[term_id].readBuffer, terms[term_id].char_num);
    //     return terms[term_id].char_num;
    // }
    // return 0;
    // TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

/*Write the contents of the buffer referenced by buf to the terminal term_id. The length of the buffer in bytes is given by len

*/
int TtyWrite(int term_id, void *buf, int len) {
    return 0;
    TracePrintf(0,"kernel_fork ERROR: not enough phys mem for creat Region0.\n");
}

void add_readyQ(pcb *p) {
    pcb *temp = readyQ;
    if (temp == NULL) {
        readyQ = p;
        p->readynext = NULL;
        p->readypre = NULL;
        TracePrintf(2, "3\n");
        return;
    }
    while(temp -> readynext != NULL) {
        temp = temp->readynext;
    }
    temp->readynext = p;
    p->readynext = NULL;
    p->readypre = temp;
    TracePrintf(2, "ready complete\n");
}

// add a process into the readyqueue
// void add_readyQ(pcb *p) {
//     TracePrintf(2, "Add a new process to ready queue\n");
//     if (readyQ == NULL) {
//         readyQ = p;
//         return;}
//     pcb *temp = readyQ;
//     while (temp->readynext != NULL) {
//         temp = temp->readynext;
//     }
//     temp->readynext = p;
//     TracePrintf(2, "ready complete\n");
// }

pcb *get_readyQ() {
    if (readyQ == NULL) {
        return ERROR;
    }
    pcb *tmp = readyQ;
    readyQ = readyQ->readynext;
    tmp->readynext = NULL;
    return tmp;
}

void add_delayQ(pcb *p) {
    // Add Current Process to the tail of delayQ
    pcb *temp = delayQ;
    if (temp == NULL) {
        delayQ = p;
        p->delaynext = NULL;
        p->delaypre = NULL;
        return;
    }

    while(temp->delaynext != NULL) {
        temp = temp->delaynext;
    }
    p->delaypre = temp;
    p->delaynext = temp->delaynext;
    temp->delaynext = p;
}

 void add_waitQ(pcb *p) {
//     pcb *tmp = waitQ;
//     while(tmp != NULL) {
//         tmp = tmp->waitnext;
//     }
   //  *tmp = p;
 }

// pcb *get_waitQ() {
//     if (waitQ == NULL) {
//         return ERROR;
//     }
//     pcb *tmp = waitQ;
//     waitQ = waitQ->waitnext;
//     tmp->waitnext = NULL;
//     return tmp;
// }

void add_childQ(pcb *p) {
    ChildNode *tmp;
    tmp = cur_Proc->parent->childQ;
    if (tmp == NULL) {
        tmp = (ChildNode*) malloc(sizeof(ChildNode));
        cur_Proc->parent->childQ = tmp;
        tmp->node = p;
        tmp->next = NULL;
    } else {
        while(tmp->next!=NULL)
            tmp = tmp->next;
        tmp->next = (ChildNode*) malloc(sizeof(ChildNode));
        tmp = tmp->next;
        tmp->node = p;
        tmp->next = NULL;
    }
}

void delete_child(pcb *p) {
    // if (p->parent->child_num == 0) {
    //     return;
    // }
    // pcb *tmp = p->parent->childQ;
    // while(tmp->childnext != NULL) {
    //     if (tmp->childnext->pid == p->pid) {
    //         tmp->childnext = tmp->childnext->childnext;
    //         p->parent->child_num--;
    //         return;
    //     }
    //     tmp = tmp->childnext;
    // }
}
// get the first child of the given pcb p
// Child get_childQ(pcb *p) {
//     Child
// }

// add pcb p's pid and status to the statusQ of its parent
void add_statusQ(int status) {
    ChildStatus *tmp;
    tmp = cur_Proc->parent->statusQ;
    if (tmp == NULL) {
        tmp = (ChildStatus*) malloc(sizeof(ChildStatus));
        cur_Proc->parent->statusQ = tmp;
        tmp->pid = cur_Proc->pid;
        tmp->status = status;
        tmp->next = NULL;
    } else {
        while(tmp->next!=NULL)
        tmp = tmp->next;
        tmp->next = (ChildStatus*) malloc(sizeof(ChildStatus));
        tmp = tmp->next;
        tmp->pid = cur_Proc->pid;
        tmp->status = status;
        tmp->next = NULL;
    }
}

// ChildStatus *get_statusQ(pcb *p) {
//     if (p->statusQ == NULL)
//         return ERROR;
//     ChildStatus *tmp = p->statusQ;
//     p->statusQ = p->statusQ->next;
//     return tmp;
// }

// find out the bottom of the user stack
unsigned long user_stack_bott() {
    unsigned long bottom;
    bottom = KERNEL_STACK_BASE >> PAGESHIFT - 1;
    while (process_page_table[bottom].valid == 1)
        bottom--;
    return bottom;
}

/**
 * Return a free page pfn from the linked list
 */
unsigned long find_free_page() {
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

/*
*   free the physical frame
*   para: the page entry contains frame to be freedmake

*/
int free_used_page(pte page_entry) {
    free_page *newpage = (free_page*)malloc(sizeof(free_page));
    TracePrintf(0,"newpage complag\n");
    newpage->phys_page_num = page_entry.pfn;
    newpage->next = head->next;
    head->next = newpage;
    page_entry.valid = 0;
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

        unsigned long idx = ((long)va-VMEM_1_BASE)>>PAGESHIFT;
        return (kernel_page_table[idx].pfn<<PAGESHIFT|((long)va&PAGEOFFSET));
      //  TracePrintf(2, "Va to Pa: Virtual address in region 1\n");
      //  return (void *)((long)kernel_page_table[((long)DOWN_TO_PAGE(va) - VMEM_1_BASE) >> PAGESHIFT].pfn*PAGESIZE + ((long)va & PAGEOFFSET)) ;
    } else {
        TracePrintf(2, "Va to Pa: Virtual address in region 0\n");
        unsigned long idx = ((long)va-VMEM_0_BASE)>>PAGESHIFT;
        return (kernel_page_table[idx].pfn<<PAGESHIFT | ((long)va & PAGEOFFSET));

      //  return (void *)((long)cur_Proc->page_table[((long)DOWN_TO_PAGE(va) - VMEM_0_BASE) >> PAGESHIFT].pfn);
    }
}

// find the first unused pte number in the current process's page table
// unsigned long buf_region0() {
//     if (free_page_num <= 0) return -1;
//     unsigned long entry_number;
//     pcb* curr = cur_Proc;
//     pte* curr_table = curr->page_table;
//     unsigned long i;
//     for (i = MEM_INVALID_PAGES; i < PAGE_TABLE_LEN - 5; i++) {
//         if (!curr_table[i].valid){
//             curr_table[i].valid = 1;
//             curr.kprot = PROT_READ | PROT_WRITE;
//             curr.uprot = PROT_READ | PROT_EXEC;
//             curr.pfn = find_free_page();
//             entry_number = i;
//             return entry_number;
//         }
//     }
//     return -1;
// }

// return entry number of kernel page table
unsigned long buf_region1() {
    TracePrintf(0, "buf_region1 is called\n");
    if (free_page_num <= 0) return -1;
    unsigned long entry_number;
    pte* curr_table = kernel_page_table;
    unsigned long i;
    for (i = 0; i < PAGE_TABLE_LEN; i++) {
        if (!curr_table[i].valid){
            curr_table[i].valid = 1;
            curr_table[i].kprot = PROT_READ | PROT_WRITE;
            curr_table[i].uprot = PROT_NONE;
            curr_table[i].pfn = find_free_page();
            WriteRegister(REG_TLB_FLUSH, (RCS421RegVal) ((void*) (long) ((i * PAGESIZE) + VMEM_1_BASE)));
            entry_number = i;
            return entry_number;
        }
    }
    return -1;
}

// used to allocate physical memory for page table after valid virtual memory
// init the page table's virtual address and half
unsigned long pa_next_table;
int half = 0; // 1 is not half
void allocPageTable(pcb* p) {
    TracePrintf(0, "allocate is used\n");
    if (half == 0) {
        unsigned long entry_num = buf_region1();
        kernel_page_table[entry_num].pfn = find_free_page();
        kernel_page_table[entry_num].valid = 1;
        kernel_page_table[entry_num].kprot = PROT_READ|PROT_WRITE;
        kernel_page_table[entry_num].uprot = PROT_NONE;
        WriteRegister(REG_TLB_FLUSH,TLB_FLUSH_1);
        pa_next_table = entry_num * PAGESIZE + VMEM_1_BASE;
        p->page_table = (pte*) pa_next_table;
        half = 1;
        pa_next_table += PAGESIZE / 2;
    } 
    else {
        p->page_table = (pte*) pa_next_table;
        half = 0;
    }
}


