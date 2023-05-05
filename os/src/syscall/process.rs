//! Process management syscalls
use crate::{
    config::{MAX_SYSCALL_NUM, CLOCK_FREQ},
    task::{
        change_program_brk, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus, TaskInfo as Info, current_user_mem_set
    }, timer::{get_time, get_time_us}, mm::{VirtAddr, MapPermission},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let time = get_time_us();
    let sec = time / 1000000;
    let usec = time % 1000000;
    if let Some(prt) = VirtAddr(_ts as usize).get_mut() {
        *prt = TimeVal {
            sec, usec
        };
        0
    } else {
        -1
    }
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    let taskinfo = Info::taskinfo_va().get_mut::<Info>().unwrap();
    if let Some(ptr) = VirtAddr(_ti as usize).get_mut::<TaskInfo>() {
        let _time = get_time() - taskinfo.start_time;
        let time = _time / (CLOCK_FREQ / 1000);
        ptr.status = TaskStatus::Running;
        ptr.time = time;
        ptr.syscall_times = taskinfo.syscall_times;
        0
    } else {
        -1
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    let start = VirtAddr(_start);
    let end = VirtAddr(_start + _len);
    if !((_port & !7usize) == 0) { return -1 }
    if !VirtAddr(_start).aligned() {return -1 }
    let mem_set = current_user_mem_set();
    if mem_set.already_in_range(start, end) {return -1}
    let permis = {
        (_port << 1) as u8
    };
    mem_set.mmap(start, end, MapPermission::from_bits(permis).unwrap());
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
