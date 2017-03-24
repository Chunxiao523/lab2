
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
 * Page table for the region 1
 */
struct pte *kernel_page_table;
/*
 * The table used to store the interrupts
 */
typedef void (*interrupt_handler)(ExceptionInfo *info);
/* 
 * Data structure of process
 */
typedef struct pcb {
    SavedContext *ctx;
    int pid;
} pcb;

/*
 * Linked list to store the free pages
 */
free_page *head;

int free_page_num = 0;

struct pte *process_page_table;


pcb *idle;

void TrapKernel(ExceptionInfo *info);
void TrapClock(ExceptionInfo *info);
void TrapIllegal(ExceptionInfo *info);
void TrapMemory(ExceptionInfo *info);
void TrapMath(ExceptionInfo *info);
void TrapTTYReceive(ExceptionInfo *info);
void TrapTTYTransmit(ExceptionInfo *info);
unsigned long find_free_page();
void allocPageTable(pcb* p);

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
	printf("12321232123");
    TracePrintf(1, "kernel_start: KernelStart called with num physical pages: %d.\n", pmem_size/PAGESIZE);
    free_page_num = 0;
	kernel_cur_break = orig_brk;

	kernel_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);
	process_page_table = (struct pte*)malloc(PAGE_TABLE_SIZE);
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
    TracePrintf(2, "kernel_start: interrupt table initialized.\n");

    /* initialize the free phys pages list */
    head = (free_page*) malloc(sizeof(free_page));
//	free_page *pointer = head;
//    for(i = PMEM_BASE; i < PMEM_BASE + pmem_size; i += PAGESIZE) {
//        pointer->next = (free_page*) malloc(sizeof(free_page));
//        pointer = pointer->next;
//        pointer->phys_page_num = free_page_num;
//        free_page_num++;
//    }
//
//    pointer = head;
//	free_page *t;
//    while (pointer->next!=NULL) {
//        if (pointer->next->phys_page_num >= (KERNEL_STACK_BASE>>PAGESHIFT) && pointer->next->phys_page_num<((unsigned long)kernel_cur_break>>PAGESHIFT)) {
//            t = pointer->next;
//            pointer->next = pointer->next->next;
//            free_page_num --;
//            free(t);
//        }
//        else pointer = pointer->next;
//    }


	/*
     * Initialize the page table and page table register for region 1 and 0
     */

	WriteRegister(REG_PTR1,(RCS421RegVal)(kernel_page_table));
	TracePrintf(2, "kernel_start: free physical address list initialized.\n");
	unsigned long addr;
    for (addr = VMEM_1_BASE; addr<(unsigned long)(&_etext); addr+=PAGESIZE) {
		TracePrintf(2, "haha %d.\n", addr);

		TracePrintf(2, "hahaha %d.\n", (unsigned long)(&_etext));
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
		TracePrintf(2, "hahahaha %d.\n", 8);
        kernel_page_table[i].pfn = addr>>PAGESHIFT; //page frame number
		TracePrintf(2, "hahahaha %d.\n", 7);
        kernel_page_table[i].valid = 1;
		TracePrintf(2, "hahahaha %d.\n", 6);
        kernel_page_table[i].kprot = PROT_READ|PROT_EXEC;
		TracePrintf(2, "hahahaha %d.\n", 5);
        kernel_page_table[i].uprot = PROT_NONE;
		TracePrintf(2, "hahahahahaha\n");
    }

	TracePrintf(2, "1.\n");

    for (; addr<(unsigned long)kernel_cur_break; addr += PAGESIZE) {
        i = (addr-VMEM_1_BASE)>>PAGESHIFT;
        kernel_page_table[i].pfn = addr>>PAGESHIFT;
        kernel_page_table[i].valid = 1;
        kernel_page_table[i].kprot = PROT_READ|PROT_WRITE;
        kernel_page_table[i].uprot = PROT_NONE;
    }

	TracePrintf(2, "2.\n");

	for (; addr<VMEM_1_LIMIT; addr += PAGESIZE) {
		i = (addr-VMEM_1_BASE)>>PAGESHIFT;
		kernel_page_table[i].valid = 0;
	}
    TracePrintf(2, "kernel_start: region 1 page table initialized.\n");

    WriteRegister(REG_PTR0, (RCS421RegVal)(process_page_table));
    for (addr = KERNEL_STACK_BASE; addr <= VMEM_0_LIMIT; addr+= PAGESIZE) {
    	i = (addr - VMEM_0_BASE)>>PAGESHIFT; //VMEM_0_BASE = 0
    	process_page_table[i].pfn = addr>>PAGESHIFT;
        process_page_table[i].valid = 1;
        process_page_table[i].kprot = PROT_READ|PROT_WRITE;
        process_page_table[i].uprot = PROT_NONE;
    }
	for (addr = VMEM_0_BASE; addr<KERNEL_STACK_BASE; addr += PAGESIZE) {
		i = (addr-VMEM_0_BASE)>>PAGESHIFT;
		process_page_table[i].valid = 0;
	}
    TracePrintf(2, "kernel_start: region 0 page table initialized.\n");


	/* enable the virtual memory subsystem */
	WriteRegister(REG_VM_ENABLE, 1);
	vir_mem = 1;
    TracePrintf(2, "kernel_start: virtual memory enabled.\n");

	/*
	 * Create idle and init process
	 */
//	idle = (pcb*)malloc(sizeof(pcb));
//    idle->pid = 0;
//    //allocPageTable(idle);
//    idle->ctx=(SavedContext*)malloc(sizeof(SavedContext));

    LoadProgram("idle",cmd_args,info);
    TracePrintf(2, "kernel_start: idle process pcb initialized.\n");

}

int SetKernelBrk(void *addr) {
	TracePrintf(2, "Setting kernel brk.\n");
	if (*(unsigned long *)addr >= VMEM_1_LIMIT || *(unsigned long *)addr < VMEM_1_BASE) return -1;
	if (vir_mem == 0) {
		kernel_cur_break = addr;
	} else {
		// first allocate free memory of size *addr - *kernel_brk from list of free phisical memory
		// second map these new free phisical memory to page_table_1
		// then grow kernel_brk to addr frame by frame
		if(addr > kernel_cur_break) {
			int i;
            if ( DOWN_TO_PAGE(*(unsigned long *)addr) - UP_TO_PAGE(kernel_cur_break) > PAGESIZE*free_page_num) return -1;
			/* Given a virtual page number, assign a physical page to its corresponding pte entry */
			for(i = (UP_TO_PAGE(kernel_cur_break) - VMEM_1_BASE)>>PAGESHIFT; i < (UP_TO_PAGE(addr) - VMEM_1_BASE)>>PAGESHIFT; i++) {
                kernel_page_table[i].pfn = find_free_page();
                kernel_page_table[i].valid = 1;
                kernel_page_table[i].kprot = PROT_READ|PROT_WRITE;
                kernel_page_table[i].uprot = PROT_NONE;
			}
		} else {
//			if(( *(unsigned long*)kernel_cur_break - DOWN_TO_PAGE(*(unsigned long*)addr))/PAGESIZE >=2)
//			{
//				for (i = 0; i < ( *(unsigned long*)kernel_cur_break - DOWN_TO_PAGE(*(unsigned long*)addr))/PAGESIZE -1;i++)
//				{
//					int tmp = kernel_page_table[(*(unsigned long*)kernel_cur_break-VMEM_1_BASE)/PAGESIZE-1].pfn;
//					*(int *)(*(unsigned long*)kernel_cur_break - PAGESIZE) = -1;
//					kernel_page_table[(*(unsigned long*)kernel_cur_break-VMEM_1_BASE)/PAGESIZE-1].pfn = nPF;
//					WriteRegister(REG_TLB_FLUSH,*(unsigned long*)kernel_brk-PAGESIZE);
//					*(int *)(*(unsigned long*)kernel_brk - PAGESIZE) = tmp;
//					nPF = tmp;
//					numOfFPF++;
//					PTR1[(*(unsigned long*)kernel_brk-VMEM_1_BASE)/PAGESIZE-1].valid = 0;
//					*(unsigned long*)kernel_brk -= PAGESIZE;
//				}
//			}
		}
		kernel_cur_break = UP_TO_PAGE(addr);
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
unsigned long find_free_page() {
        if (head->next==NULL) return 0;
		free_page *tmp = head->next;
        head->next = tmp->next;
        free_page_num--;
        unsigned long ret = tmp->phys_page_num;
        free(tmp);
        return ret;
}
//void allocPageTable(pcb* p)
//{
//    if (half_full==0) {
//        /* set appropriate virtual start address for r0 page table */
//        p->pt_r0 = (pte*)next_PT_vaddr;
//        next_PT_vaddr += PAGESIZE/2;
//        half_full=1;
//        /* get physical frame for r0 page table
//         * set the r1 page table entry for the start address of r0 page table */
//        unsigned long idx = ((unsigned long)(p->pt_r0)-VMEM_1_BASE)>>PAGESHIFT;
//        if(pt_r1[idx].valid) {
//            kernel_Exit(ERROR);
//        }
//        process_page_table[idx].pfn = getFreePage();
//        process_page_table[idx].valid = 1;
//        process_page_table[idx].kprot = PROT_READ|PROT_WRITE;
//        process_page_table[idx].uprot = PROT_NONE;
//    }
//    else {
//        /* set appropriate virtual start address for r0 page table */
//        p->pt_r0 = (struct pte*)next_PT_vaddr;
//        next_PT_vaddr -= PAGESIZE*3/2;
//
//
//        /* whole frame is used, so clear half_full_vaddr and half_full_frame */
//        half_full=0;
//    }
//}