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

#ifndef FILEBOX_BPF_H
#define FILEBOX_BPF_H

#include "linux_defs.h"
#include "pybpf.bpf.h"

#define FILEBOX_TASKS_MAP_SIZE  10240
#define FILEBOX_POLICY_MAP_SIZE 10240

#define FILEBOX_DECISION_NONE  0x00000000
#define FILEBOX_DECISION_ALLOW 0x00000001
#define FILEBOX_DECISION_AUDIT 0x00000002
#define FILEBOX_DECISION_DENY  0x00000004

#define FILEBOX_FILE_NONE   0x00000000
#define FILEBOX_FILE_READ   0x00000001
#define FILEBOX_FILE_WRITE  0x00000002
#define FILEBOX_FILE_APPEND 0x00000004
#define FILEBOX_FILE_EXEC   0x00000008
#define FILEBOX_FILE_UNLINK 0x00000010
#define FILEBOX_FILE_RENAME 0x00000020

typedef struct filebox_inode_key_t {
    u32 st_ino;
    u32 st_dev;
} filebox_inode_key_t;

typedef struct filebox_task_state_t {
    filebox_inode_key_t executable_key;
} filebox_task_state_t;

typedef struct filebox_policy_key_t {
    filebox_inode_key_t inode_key;
    filebox_inode_key_t executable_key;
} filebox_policy_key_t;

typedef struct filebox_policy_t {
    u32 allow;
    u32 audit;
    u32 deny;
} filebox_policy_t;

typedef struct filebox_inode_audit_info_t {
    u32 pid;
    u32 access;
    u32 decision;
    filebox_inode_key_t executable_key;
    filebox_inode_key_t inode_key;
} filebox_inode_audit_info_t;

typedef struct execve_event_t {
    u32 pid;
    filebox_inode_key_t executable_key;
    char comm[16];
} execve_event_t;

#endif /* ifndef FILEBOX_BPF_H */
