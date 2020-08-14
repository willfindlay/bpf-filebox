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

#ifndef FILEBOX_LINUX_DEFS_H
#define FILEBOX_LINUX_DEFS_H

#include "pybpf.bpf.h"

#define PATH_MAX 4096

/* /include/linux/fs.h */
#define MAY_EXEC      0x00000001
#define MAY_WRITE     0x00000002
#define MAY_READ      0x00000004
#define MAY_APPEND    0x00000008
#define MAY_ACCESS    0x00000010
#define MAY_OPEN      0x00000020
#define MAY_CHDIR     0x00000040
#define MAY_NOT_BLOCK 0x00000080

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev)&MINORMASK))

static inline u32 new_encode_dev(dev_t dev)
{
    unsigned major = MAJOR(dev);
    unsigned minor = MINOR(dev);
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

#define EPERM 1

#endif /* ifndef FILEBOX_LINUX_DEFS_H */
