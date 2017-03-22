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
	kernel_page_table = (pte*)malloc(PAGE_TABLE_SIZE);
	process_page_table = (pte*)malloc(PAGE_TABLE_SIZE);
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
	 for (i=7; i<TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table[i] = NULL;
    }
	WriteRegister(REG_VECTOR_BASE, interrupt_vector_table);


	/* 
     * Initialize the page table and page table register for region 1 and 0
     */

	WriteRegister(REG_PTR1,(RCS421RegVal)(kernel_page_table));
	long addr;
	int i;
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
    idle->pid = next_pid++;
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
				pt_r1[i].pfn = getFreePage();
                pt_r1[i].valid = 1;
                pt_r1[i].kprot = PROT_READ|PROT_WRITE;
                pt_r1[i].uprot = PROT_NONE;
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
	 printf("[TRAP_ILLEGAL] Trapped Illegal Instruction, pid %d\n", pid);
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
	 	case TRAP_ILLEGAL__KERNELI:
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
