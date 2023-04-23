# 实现功能

实现了`sys_task_info`系统调用
1. 通过在`TaskControlBlock`中加入指向当前程序`TaskInfo`存储区的指针`&'static TaskInfo`来获得当前应用信息。
2. 在`task/mod.rs`中添加了`syscall_plus(usize)`与`task_info()->&'static TaskInfo`来分别记录系统调用次数与获得应用信息。

# 简答作业

1. 三个bad测例，一个访问了地址`0x0`，一个使用了S特权级指令`sret`，一个使用了S特权级指令`csrr`，使用的sbi为仓库里自带的sbi。其内核报错如下：
    - PageFault in application, bad addr = 0x0, bad instruction = 0x80400414, kernel killed it.
    - IllegalInstruction in application, kernel killed it.
    - IllegalInstruction in application, kernel killed it.
2. 
    1. `a0`代表了当前应用内核栈的栈顶地址，执行该指令时`a0`总指向应用内核栈栈底向上偏移一个`TrapContext`大小的位置。一种使用是在应用刚开始运行时切换到用户态，另一种是在ecall或者switch后返回用户态。
    2. 特殊处理了`sstatus` `sepc` `sscratch`三个寄存器，`sstatus`记录了处理器状态信息，如当前trap前后特权级，是否忽略中断等；`sepc`记录了回到用户态后开始执行的第一条指令位置；`sscratch`用作临时保存`sp`指针以便恢复其他寄存器。
    3. 因为`x2`目前保存着内核栈顶，恢复其它寄存器依赖于该寄存器的值，因此需要最后保存，跳过`x4`是因为该寄存器目前不需要恢复。
    4. `sp`指向用户栈栈顶`sscratch`指向内核栈栈顶。
    5. 切换在`sret`指令后，该指令会将`sstatus`权限位设置为用户模式。
    6. `sp`指向内核栈栈顶`sscratch`指向用户栈栈顶。
    7. 是在`user/src/syscall.rs`中`syscall`函数中`ecall`指令执行时发生的。

