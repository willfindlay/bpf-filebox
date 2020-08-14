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

from __future__ import annotations
import os
import ctypes as ct
from enum import IntEnum, IntFlag as _IntFlag, auto, _decompose

class IntFlag(_IntFlag):
    def names(self):
        """
        Return a | joined list of names.
        """
        members, _uncovered = _decompose(self.__class__, self._value_)
        return '|'.join([str(m._name_ or m._value_) for m in members])

class FileAccess(IntFlag):
    """
    Represents FILEBOX_FILE_* flags.
    """
    NONE     = 0
    READ     = auto()
    WRITE    = auto()
    APPEND   = auto()
    EXEC     = auto()
    UNLINK   = auto()
    RENAME   = auto()

class PolicyDecision(IntFlag):
    """
    Represents FILEBOX_DECISION_* flags.
    """
    NONE  = 0
    ALLOW = auto()
    AUDIT = auto()
    DENY  = auto()

class InodeKey(ct.Structure):
    """
    An inode, device pair.
    """
    _fields_ = (
            ('st_ino', ct.c_uint32),
            ('st_dev', ct.c_uint32),
            )

    def flatten(self):
        return self.st_ino | (self.st_dev << 32)

    @staticmethod
    def from_pathname(pathname: str) -> InodeKey:
        s = os.stat(pathname)
        k = InodeKey()
        k.st_ino = s.st_ino
        k.st_dev = s.st_dev
        return k

class TaskState(ct.Structure):
    """
    Represents filebox_task_state_t struct.
    """
    _fields_ = (
            ('executable_key', InodeKey),
            )

class PolicyKey(ct.Structure):
    """
    Represents filebox_policy_key_t struct.
    """
    _fields_ = (
            ('inode_key', InodeKey),
            ('executable_key', InodeKey),
            )

class Policy(ct.Structure):
    """
    Represents filebox_policy_t struct.
    """
    _fields_ = (
            ('allow', ct.c_uint32),
            ('audit', ct.c_uint32),
            ('deny', ct.c_uint32),
            )

class InodeAuditInfo(ct.Structure):
    """
    Represents filebox_inode_audit_info_t struct.
    """
    _fields_ = (
            ('pid', ct.c_uint32),
            ('access', ct.c_uint32),
            ('decision', ct.c_uint32),
            ('executable_key', InodeKey),
            ('inode_key', InodeKey),
            )

class ExecveEvent(ct.Structure):
    """
    Represents execve_event_t struct.
    """
    _fields_ = (
            ('pid', ct.c_uint32),
            ('executable_key', InodeKey),
            ('comm', (ct.c_char * 16))
            )
