/*
 * filebox  A BPF security daemon that enforces access control on inodes.
 * Copyright (C) 2020  William Findlay
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * 2020-Aug-13  William Findlay  Created this.
 */

#include "filebox.bpf.h"

/* ========================================================================= *
 * Maps                                                                      *
 * ========================================================================= */

/* Maps pid -> filebox_task_t */
BPF_HASH(task_states, u32, filebox_task_state_t, FILEBOX_TASKS_MAP_SIZE, 0);

/* Maps (executable_key, inode_key) -> filebox_policy_t */
BPF_HASH(inode_policy, filebox_policy_key_t, filebox_policy_t,
         FILEBOX_POLICY_MAP_SIZE, 0);

/* Stores whether an inode is currently enforcing. Used for default deny. */
BPF_HASH(inode_enforcing, filebox_inode_key_t, bool, FILEBOX_POLICY_MAP_SIZE,
         0);

BPF_RINGBUF(audit_inode_events, 4);

static __always_inline void audit_inode(u32 pid, u32 access, u32 decision,
                                        filebox_inode_key_t executable_key,
                                        filebox_inode_key_t inode_key)
{
    if (!(decision & FILEBOX_DECISION_AUDIT ||
          decision & FILEBOX_DECISION_DENY)) {
        return;
    }

    filebox_inode_audit_info_t *event = bpf_ringbuf_reserve(
        &audit_inode_events, sizeof(filebox_inode_audit_info_t), 0);

    if (event) {
        event->pid = pid;
        event->access = access;
        event->decision = decision;
        event->executable_key = executable_key;
        event->inode_key = inode_key;

        bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

BPF_RINGBUF(on_execve_events, 4);

static __always_inline void on_execve(u32 pid,
                                      filebox_inode_key_t executable_key,
                                      struct linux_binprm *bprm)
{
    execve_event_t *event =
        bpf_ringbuf_reserve(&on_execve_events, sizeof(execve_event_t), 0);

    if (event) {
        event->pid = pid;
        event->executable_key = executable_key;

        // FIXME: most of this nonsense won't be necessary when we have
        // bpf_d_path
        struct path f_path;
        BPF_CORE_READ_INTO(&f_path, bprm, file, f_path);
        struct qstr d_name;
        BPF_CORE_READ_INTO(&d_name, f_path.dentry, d_name);
        bpf_core_read_str(event->comm, sizeof(event->comm), d_name.name);

        bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

/* ========================================================================= *
 * Helper Functions                                                          *
 * ========================================================================= */

static __always_inline filebox_inode_key_t inode_to_key(struct inode *inode)
{
    filebox_inode_key_t key = {};

    BPF_CORE_READ_INTO(&key.st_ino, inode, i_ino);

    u32 s_dev = 0;
    BPF_CORE_READ_INTO(&s_dev, inode, i_sb, s_dev);

    key.st_dev = new_encode_dev(s_dev);

    return key;
}

/* Convert a Linux mode and permission mask to an access vector. */
static __always_inline u32 file_mask_to_access(int mask)
{
    u32 access = FILEBOX_FILE_NONE;

    if (mask & MAY_EXEC)
        access |= FILEBOX_FILE_EXEC;
    if (mask & MAY_READ)
        access |= FILEBOX_FILE_READ;

    if (mask & MAY_APPEND)
        access |= FILEBOX_FILE_APPEND;
    else if (mask & MAY_WRITE)
        access |= FILEBOX_FILE_WRITE;

    return access;
}

static __always_inline u32 policy_decision(u32 requested,
                                           filebox_policy_t *policy)
{
    u32 decision = FILEBOX_DECISION_NONE;

    if (requested & policy->deny)
        return FILEBOX_DECISION_DENY;

    if (requested & policy->audit)
        decision |= FILEBOX_DECISION_AUDIT;

    if ((requested & policy->allow) == requested)
        decision |= FILEBOX_DECISION_ALLOW;
    else
        decision |= FILEBOX_DECISION_DENY;

    return decision;
}

/* ========================================================================= *
 * BPF Programs                                                              *
 * ========================================================================= */

SEC("lsm/bprm_check_security")
int BPF_PROG(do_bprm_check_security, struct linux_binprm *bprm)
{
    u32 pid = bpf_get_current_pid_tgid();
    filebox_task_state_t s = {};
    s.executable_key = inode_to_key(bprm->file->f_inode);

    bpf_map_update_elem(&task_states, &pid, &s, 0);

    on_execve(pid, s.executable_key, bprm);

    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(do_task_alloc, struct task_struct *task)
{
    filebox_task_state_t *parent_state;
    filebox_task_state_t *child_state;

    struct task_struct *c = task;
    struct task_struct *p = task->parent;

    u32 ppid = p->pid;

    // Look up parent task state if it exists
    parent_state = bpf_map_lookup_elem(&task_states, &ppid);
    if (!parent_state) {
        return 0;
    }

    u32 cpid = c->pid;

    child_state = bpf_map_lookup_or_try_init(&task_states, &cpid, parent_state);
    if (!child_state) {
        // TODO: log error
        return 0;
    }

    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(do_task_free, struct task_struct *task)
{
    u32 pid = task->pid;

    bpf_map_delete_elem(&task_states, &pid);

    return 0;
}

static __always_inline int do_inode_permission_common(struct inode *inode,
                                                      u32 access)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 decision = 0;

    if (!access) {
        return 0;
    }

    filebox_policy_key_t policy_key = {};
    policy_key.inode_key = inode_to_key(inode);

    bool inode_is_enforcing =
        (bool)bpf_map_lookup_elem(&inode_enforcing, &policy_key.inode_key);

    filebox_task_state_t *s = bpf_map_lookup_elem(&task_states, &pid);

    if (!s) {
        if (inode_is_enforcing) {
            decision = FILEBOX_DECISION_DENY;
            goto out;
        } else {
            return 0;
        }
    }

    policy_key.executable_key = s->executable_key;

    filebox_policy_t *policy = bpf_map_lookup_elem(&inode_policy, &policy_key);

    if (!policy) {
        if (inode_is_enforcing) {
            decision = FILEBOX_DECISION_DENY;
            goto out;
        } else {
            return 0;
        }
    }

    decision = policy_decision(access, policy);

out:
    audit_inode(pid, access, decision, policy_key.executable_key,
                policy_key.inode_key);

    return decision & FILEBOX_DECISION_DENY ? -EPERM : 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(do_inode_permission, struct inode *inode, int mask)
{
    u32 access = file_mask_to_access(mask);

    return do_inode_permission_common(inode, access);
}

SEC("lsm/inode_unlink")
int BPF_PROG(do_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    int ret = do_inode_permission_common(dir, FILEBOX_FILE_WRITE);
    if (ret)
        return ret;
    return do_inode_permission_common(dentry->d_inode, FILEBOX_FILE_UNLINK);
}

SEC("lsm/inode_rename")
int BPF_PROG(do_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry)
{
    int ret = do_inode_permission_common(old_dir, FILEBOX_FILE_WRITE);
    if (ret)
        return ret;
    ret = do_inode_permission_common(old_dentry->d_inode, FILEBOX_FILE_RENAME);
    if (ret)
        return ret;
    ret = do_inode_permission_common(new_dir, FILEBOX_FILE_WRITE);
    if (ret)
        return ret;
    return do_inode_permission_common(new_dentry->d_inode, FILEBOX_FILE_UNLINK);
}

SEC("lsm/file_permission")
int BPF_PROG(do_file_permission, struct file *file, int mask)
{
    u32 access = file_mask_to_access(mask);

    struct inode *inode = file->f_inode;
    return do_inode_permission_common(inode, access);
}

char _license[] SEC("license") = "GPL";
