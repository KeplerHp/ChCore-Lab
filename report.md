#### 练习题1

1. ` sys_create_cap_group`代码补全

   ```c
   		/* cap current cap_group */
           /* LAB 3 TODO BEGIN */
           new_cap_group = obj_alloc(TYPE_CAP_GROUP, sizeof(struct cap_group));
           /* LAB 3 TODO END */
           if (!new_cap_group) {
                   r = -ENOMEM;
                   goto out_fail;
           }
           /* LAB 3 TODO BEGIN */
           /* initialize cap group */
           cap_group_init(new_cap_group, BASE_OBJECT_NUM, args.badge);
           /* LAB 3 TODO END */
   
           cap = cap_alloc(current_cap_group, new_cap_group);
           if (cap < 0) {
                   r = cap;
                   goto out_free_obj_new_grp;
           }
   
           /* 1st cap is cap_group */
           if (cap_copy(current_thread->cap_group, new_cap_group, cap)
               != CAP_GROUP_OBJ_ID) {
                   kwarn("%s: cap_copy fails or cap[0] is not cap_group\n",
                         __func__);
                   r = -ECAPBILITY;
                   goto out_free_cap_grp_current;
           }
   
           /* 2st cap is vmspace */
           /* LAB 3 TODO BEGIN */
           vmspace = obj_alloc(TYPE_VMSPACE, sizeof(struct vmspace));
           /* LAB 3 TODO END */
   ```

   使用`obj_alloc`分配对应的`cap_group`和`vmspace`对象，然后再用`cap_group_init`对新分配的`cap_group`进行初始化，设置对应的参数`BASE_OBJECT_NUM` 和 `args.badge` ，其中 `args.badge` 通过参考`cap_group_init`的函数定义可以找到。

2. `create_root_cap_group`代码补全：

   ```c
   		/* LAB 3 TODO BEGIN */
           cap_group = obj_alloc(TYPE_CAP_GROUP, sizeof(struct cap_group));
           /* LAB 3 TODO END */
           BUG_ON(!cap_group);
   
           /* LAB 3 TODO BEGIN */
           /* initialize cap group, use ROOT_CAP_GROUP_BADGE */
           cap_group_init(cap_group, BASE_OBJECT_NUM, ROOT_CAP_GROUP_BADGE);
           /* LAB 3 TODO END */
           slot_id = cap_alloc(cap_group, cap_group);
   
           BUG_ON(slot_id != CAP_GROUP_OBJ_ID);
   
           /* LAB 3 TODO BEGIN */
           vmspace = obj_alloc(TYPE_VMSPACE, sizeof(struct vmspace));
           /* LAB 3 TODO END */
           BUG_ON(!vmspace);
   
           /* fixed PCID 1 for root process, PCID 0 is not used. */
           vmspace_init(vmspace, ROOT_PROCESS_PCID);
   
           /* LAB 3 TODO BEGIN */
           slot_id = cap_alloc(cap_group, vmspace);
           /* LAB 3 TODO END */
   ```

   补充的部分基本和`sys_create_cap_group`一致，多一步对分配得到的`vmspace`对象则需要调用`cap_alloc`分配对应的`slot`

#### 练习题2

1. 第一处代码补全

   ```c
   				/* LAB 3 TODO BEGIN */
                   /* Get offset, vaddr, filesz, memsz from image*/
                   memcpy(data,
                          (void *)((unsigned long)&binary_procmgr_bin_start
                                   + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                   + PHDR_OFFSET_OFF),
                          sizeof(data));
                   offset = (unsigned int)le32_to_cpu(*(u32 *)data);
   
                   memcpy(data,
                          (void *)((unsigned long)&binary_procmgr_bin_start
                                   + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                   + PHDR_VADDR_OFF),
                          sizeof(data));
                   vaddr = (unsigned int)le32_to_cpu(*(u32 *)data);
   
                   memcpy(data,
                          (void *)((unsigned long)&binary_procmgr_bin_start
                                   + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                   + PHDR_FILESZ_OFF),
                          sizeof(data));
                   filesz = (unsigned int)le32_to_cpu(*(u32 *)data);
   
                   memcpy(data,
                          (void *)((unsigned long)&binary_procmgr_bin_start
                                   + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                   + PHDR_MEMSZ_OFF),
                          sizeof(data));
                   memsz = (unsigned int)le32_to_cpu(*(u32 *)data);
                   /* LAB 3 TODO END */
   ```

   获取对应`offset`, `vaddr`, `filesz`, `memsz`，将`PHDR_FLAGS_OFF`改成对应的`PHDR_OFFSET_OF`F等即可获取对应的数据。

2. 第二处代码补全

   ```c
                   /* LAB 3 TODO BEGIN */
                   /* Create a pmo for the segment */
                   create_pmo(memsz, PMO_DATA, root_cap_group, 0, &segment_pmo);
                   /* LAB 3 TODO END */
   ```

   根据`create_pmo`的定义，填入参数`memsz`表示对应`pmo`的大小，`pmo_type`为`PMO_DATA`，立即分配物理内存，以及对应的`cap_group`的`root_cap_group`, 物理地址是零地址，以及作为存放返回值的`pmo`对象 `segment_pmo`

3. 第三处代码补全

   ```c
                   /* LAB 3 TODO BEGIN */
                   /* Copy elf file contents into memory*/
                   memset((void *)phys_to_virt(segment_pmo->start),
                          0,
                          segment_pmo->size);
                   memcpy((void *)phys_to_virt(segment_pmo->start),
                          (void *)((unsigned long)&binary_procmgr_bin_start
                                   + offset + ROOT_BIN_HDR_SIZE),
                          filesz);
                   /* LAB 3 TODO END */
   ```

   根据代码注释需要将elf文件中的内容copy到内存中，使用`mem_set`映射虚拟内存空间，在使用`memcpy`进行copy内容

4. 第四处代码补全

   ```c
                   /* LAB 3 TODO BEGIN */
                   /* Set flags*/
                   if (flags & PHDR_FLAGS_R)
                           vmr_flags |= VMR_READ;
                   if (flags & PHDR_FLAGS_W)
                           vmr_flags |= VMR_WRITE;
                   if (flags & PHDR_FLAGS_X)
                           vmr_flags |= VMR_EXEC;
                   /* LAB 3 TODO END */
   ```

   设置`vmr_flags`，利用`flags`进行判断可读可写可执行权限，然后将对应的`vmr`权限位相或即可

#### 练习题3

代码补全：

```c
        /* LAB 3 TODO BEGIN */
        /* SP_EL0, ELR_EL1, SPSR_EL1*/
        thread->thread_ctx->ec.reg[SP_EL0] = stack;
        thread->thread_ctx->ec.reg[ELR_EL1] = func;
        thread->thread_ctx->ec.reg[SPSR_EL1] = SPSR_EL1_EL0t;
        /* LAB 3 TODO END */
```

根据代码注释，需要设置上下文中的`SP_EL0`，`SLR_EL1`，`SPSR_EL1`， 分别对应着线程的Stack pointer寄存器，异常链接寄存器，程序状态保存寄存器。因为是用户态把stack赋值给`SP_EL0`；把`func`赋给`ELR_EL1` ，在`eret`的时候可以正常跳转到`func`对应的地址；把`SPSR_EL1_EL0t`赋值给`SPSR_EL1`，实现特权级的切换。

#### 思考题4

调用关系：

`create_root_thread()`  ->  `tread_init()`  ->  `obj_get()`，`obj_put()`，`create_thread_ctx()`，         `init_thread_ctx()`，`sched()`，`eret_to_thread(switch_context())` -> `__eret_to_thread()` -> `exception_exit()` -> `eret`

创建第一个线程、进行线程初始化的时候，包括分配`cap_group`，`vmspace`，然后进行上下文初始化等；

`sched()` 进行了一次调度，在调度队列中选出线程；

然后通过`switch_context()`进行上下文的切换，将`cpu_info`中记录的当前CPU线程的上下文记录为被选择的线程的上下文；

`eret_to_thread()`通过调用 `__eret_to_thread()` -> `exception_exit()` -> `eret`，跳转到选出的线程的用户态。

#### 练习题5

对于`sycn_el1h`的情况，跳转到`handle_entry_c`；对`rq_el1t`、`fiq_el1t`、`fiq_el1h`、`error_el1t`、`error_el1h`、`sync_el1t` ，跳转到`unexpected_handler`

#### 练习题6

1. 补全代码`exception_enter`

   ```assembly
   .macro	exception_enter
   
   	/* LAB 3 TODO BEGIN */
   	
   	sub sp, sp, #ARCH_EXEC_CONT_SIZE
   	stp	x0, x1, [sp, #16 * 0]
   	stp	x2, x3, [sp, #16 * 1]
   	stp	x4, x5, [sp, #16 * 2]
   	stp	x6, x7, [sp, #16 * 3]
   	stp	x8, x9, [sp, #16 * 4]
   	stp	x10, x11, [sp, #16 * 5]
   	stp	x12, x13, [sp, #16 * 6]
   	stp	x14, x15, [sp, #16 * 7]
   	stp	x16, x17, [sp, #16 * 8]
   	stp	x18, x19, [sp, #16 * 9]
   	stp	x20, x21, [sp, #16 * 10]
   	stp	x22, x23, [sp, #16 * 11]
   	stp	x24, x25, [sp, #16 * 12]
   	stp	x26, x27, [sp, #16 * 13]
   	stp	x28, x29, [sp, #16 * 14]
   
   	/* LAB 3 TODO END */
   
   	mrs	x21, sp_el0
   	mrs	x22, elr_el1
   	mrs	x23, spsr_el1
   
   	/* LAB 3 TODO BEGIN */
   	
   	stp	x30, x21, [sp, #16 * 15]
   	stp	x22, x23, [sp, #16 * 16]
   
   	/* LAB 3 TODO END */
   
   .endm
   ```

   先把`sp`减去 `#ARCH_EXEC_CONT_SIZE`，预留出存储上下文的空间 把x0-x29通用寄存器中的值，存入到内存中 用`mr`把`sp_el0` 、`elr_el1`、 `sprs_el1`中的值存到寄存器中，并把x30 LinkResigter都存到内存中。

2. 补全代码`exception_exit`

   

   ```assembly
   .macro	exception_exit
   
   	/* LAB 3 TODO BEGIN */
   
   	ldp	x30, x21, [sp, #16 * 15] 
   	ldp	x22, x23, [sp, #16 * 16]
   
   	/* LAB 3 TODO END */
   
   	msr	sp_el0, x21
   	msr	elr_el1, x22
   	msr	spsr_el1, x23
   
   	/* LAB 3 TODO BEGIN */
   
   	ldp	x0, x1, [sp, #16 * 0]
   	ldp	x2, x3, [sp, #16 * 1]
   	ldp	x4, x5, [sp, #16 * 2]
   	ldp	x6, x7, [sp, #16 * 3]
   	ldp	x8, x9, [sp, #16 * 4]
   	ldp	x10, x11, [sp, #16 * 5]
   	ldp	x12, x13, [sp, #16 * 6]
   	ldp	x14, x15, [sp, #16 * 7]
   	ldp	x16, x17, [sp, #16 * 8]
   	ldp	x18, x19, [sp, #16 * 9]
   	ldp	x20, x21, [sp, #16 * 10]
   	ldp	x22, x23, [sp, #16 * 11]
   	ldp	x24, x25, [sp, #16 * 12]
   	ldp	x26, x27, [sp, #16 * 13]
   	ldp	x28, x29, [sp, #16 * 14]
   	add	sp, sp, #ARCH_EXEC_CONT_SIZE
   
   	/* LAB 3 TODO END */
   
   	eret
   .endm
   ```

   进行`exception_enter`的逆过程

3. 代码补全`switch_to_cpu_stack`

   ```assembly
   .macro switch_to_cpu_stack
   	mrs     x24, TPIDR_EL1
   	/* LAB 3 TODO BEGIN */
   
   	add	x24, x24, #OFFSET_LOCAL_CPU_STACK
   
   	/* LAB 3 TODO END */
   	ldr	x24, [x24]
   	mov	sp, x24
   .endm
   ```

   从`TRIDR_EL1`读取当前核的`per_cpu_info`，然后再加上`local_cpu_stack`的偏移量

#### 思考题7

在`printf`中利用`ret = vfprintf(stdout, fmt, ap)`调用`vfprintf`函数

在`vfprintf`函数中使用了`stdout (f)`的一系列操作

其中，`f->write(f, 0, 0)`对应`stdout`的`write`操作

`stdout`的`write`操作被定义为`__stdout_write`，而`stdout_write`中调用了`_stdio_write`函数

在`__stdio_write`中进一步调用了`syscall(SYS_writev, f->fd, iov, iovcnt)`的系统调用,

也就是`stdout- >fd`

在`syscall_dispatcher.c`中， `fd_dic[fd1]->fd_op = &stdout_ops`

其中`stdout_ops`中，把`write`操作定义为`chcore_stdout_write`

#### 练习题8

添加以下代码：

```c
static void put(char buffer[], unsigned size)
{
        /* LAB 3 TODO BEGIN */
        chcore_syscall2(CHCORE_SYS_putstr, (vaddr_t)buffer, size);
        /* LAB 3 TODO END */
}
```

根据提示调用`chcore_syscall`，填入对应`put`的系统调用号，以及`buffer`和`size`参数即可。

#### 练习题9

编写好hello_chcore.c文件

```c
#include <stdio.h>

int main()
{
	printf("Hello ChCore!\n");
}
```

使用`musl-gcc`编译为hello_chcore.bin文件，放在ramdisk目录下即可。
