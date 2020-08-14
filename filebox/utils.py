"""
    filebox  A BPF security daemon that enforces access control on inodes.
    Copyright (C) 2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    2020-Aug-13  William Findlay  Created this.
"""

import os
from typing import Iterator, Tuple, Optional

from proc.core import find_processes, Process

from filebox.structs import InodeKey

def module_path(path: str):
    """
    Get the path to a file within the module.
    """
    return os.path.join(os.path.realpath(os.path.dirname(__file__)), path)

def running_processes() -> Iterator[Tuple[InodeKey, str, int]]:
    """
    Returns an interator of all processes running on the
    system. Iterator contains tuples of [@executable_key, @exe, @tid]
    """
    for p in find_processes():
        exe = p.exe
        tid = p.pid
        if not exe:
            continue
        try:
            key = InodeKey.from_pathname(exe)
        except Exception:
            continue
        yield (key, exe, tid)

def running_process(pid: int) -> Optional[Tuple[InodeKey, str]]:
    p = Process.from_pid(pid)
    if not p:
        return None
    exe = p.exe
    tid = p.pid
    if not exe:
        return None
    key = InodeKey.from_pathname(exe)
    return key, exe
