//! Types related to task management

use crate::config::{MAX_SYSCALL_NUM, MAX_APP_NUM};

use super::TaskContext;

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub task_start_time: usize,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
}

pub static TASK_INFO_BLOCK: [TaskInfo; MAX_APP_NUM] = [
    TaskInfo {
        task_start_time: 0,
        syscall_times: [0; MAX_SYSCALL_NUM],
    }; MAX_APP_NUM
];

/// The task control block (TCB) of a task.
#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    /// The task status in it's lifecycle
    pub task_status: TaskStatus,
    /// The task context
    pub task_cx: TaskContext,
    /// The task info ptr
    pub task_info_ptr: &'static TaskInfo,
}

/// The status of a task
#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
