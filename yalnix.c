#include <comp421/yalnix.h>
#include <comp421/hardware.h>
/*
mid term
initializing
interrupts, enabling virtual memory, and creating the idle and init processes.
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
	/* initialize the page table and page table register*/


	/* enable the virtual memory subsystem */
	WriteRegister(REG_VM_ENABLE, 1); 
	vir_mem = 1;
}

int SetKernelBrk(void *addr) {
	if (vir_mem == 0) {
		kernel_cur_break = addr;
	} else {

	}
	return 0;
}