
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
} pcb;
/*
 * The table used to store the interrupts
 */
typedef void (*interrupt_handler)(ExceptionInfo *info);
/*
 * Linked list to store the free pages
 */
free_page *head;

int free_page_num = 0;



pcb *cur_Proc;

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
int MyGetPid();
void *va2pa(void *va);

/*
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
        pointer->phys_page_num = free_page_num;
        free_page_num++;
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

    WriteRegister(REG_PTR0, (RCS421RegVal)(process_page_table));
    for (addr = VMEM_0_BASE; addr< KERNEL_STACK_BASE; addr += PAGESIZE) {
        i = (addr-VMEM_0_BASE)>>PAGESHIFT;
        process_page_table[i].valid = 0;
        idle_page_table[i].valid = 0;
    }
    for (addr = KERNEL_STACK_BASE; addr < VMEM_0_LIMIT; addr+= PAGESIZE) {
    	i = (addr - VMEM_0_BASE)>>PAGESHIFT; //VMEM_0_BASE = 0
        TracePrintf(2, "Kernel Start: kernel stack number %d\n", i);
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
	pcb *idle;
	idle = (pcb*)malloc(sizeof(pcb));
    idle->pid = pid;
    idle->page_table = idle_page_table;
	pid ++;
    idle->ctx=(SavedContext*)malloc(sizeof(SavedContext));
    TracePrintf(2, "Kernel Start: idle process pcb initialized.\n");
	pcb *init;
	init = (pcb *) malloc(sizeof(pcb));
	init->pid = pid;
    init->page_table = process_page_table;
	pid ++;
	init->ctx = (SavedContext *)malloc(sizeof(SavedContext));
	cur_Proc = init;

    LoadProgram("init",cmd_args,info);
    TracePrintf(2, "Kernel Start: init process pcb initialized.\n");

	ContextSwitch(MyKernelSwitchFunc, &cur_Proc->ctx, (void *) cur_Proc, (void *) idle);
    TracePrintf(2, "Kernel Start: Context Switch finished.\n");

}

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
            if ( DOWN_TO_PAGE(*(unsigned long *)addr) - UP_TO_PAGE(kernel_cur_break) > PAGESIZE*free_page_num) return -1;
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
/*
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
        unsigned long ret = tmp->phys_page_num;
//      free(tmp);
//		tmp = NULL;
        return ret;
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

               break;
           }
       }

    }
  //  p2_pt[508].valid = 1;
    WriteRegister(REG_PTR0, (RCS421RegVal)va2pa(p2_pt)); // Set the register for region 0
    TracePrintf(2, "Context Switch: Set the register for region 0， %d\n", p2_pt[508].pfn);

    TracePrintf(2, "Context Switch: Set the register for region 0， %d\n", p2_pt[508].valid);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0); // flush
    TracePrintf(2, "Context Switch: finish context switch\n");
	return &pcb_ptr2->ctx;
}

void *va2pa(void *va) {
    if (DOWN_TO_PAGE(va) >= VMEM_1_BASE) {
        return (void *)((long)kernel_page_table[((long)va - VMEM_1_BASE) >> PAGESHIFT].pfn * PAGESIZE + ((long)va & PAGEOFFSET));
    } else {
        return (void *)((long)cur_Proc->page_table[((long)va - VMEM_0_BASE) >> PAGESHIFT].pfn * PAGESIZE + ((long)va & PAGEOFFSET));
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
    // currentProc->delay_clock=clock_ticks;
    if(clock_ticks>0){
     //   ContextSwitch(MyKernelSwitchFunc,cur_Proc->ctx,cur_Proc,next_ready_queue());
    }

    return 0;
}