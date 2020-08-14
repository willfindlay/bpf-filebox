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
import ctypes as ct

from pybpf import BPFObjectBuilder

from filebox.utils import module_path, running_processes, running_process
from filebox.structs import FileAccess, PolicyDecision, TaskState, PolicyKey, Policy, InodeAuditInfo, InodeKey, ExecveEvent
from filebox.logger import get_logger

logger = get_logger()

class BPFProgram:
    def __init__(self):
        self.bpf = None
        self.executables = {}

    def load_bpf(self, recompile=False) -> None:
        """
        Load the BPF program.
        """
        assert self.bpf is None

        builder = BPFObjectBuilder()

        # Recompile if desired
        if recompile:
            logger.info('Compiling BPF program...')
            builder.generate_skeleton(module_path('bpf/filebox.bpf.c'))
        else:
            # Otherwise try to use existing skeleton and fall back to
            # recompilation
            try:
                builder.use_existing_skeleton(module_path('bpf/.output/filebox.skel.so'))
            except Exception as e:
                logger.warn(f'Unable to load pre-existing skeleton due to: {e}')
                logger.info(f'Falling back to compilation...')
                builder.generate_skeleton(module_path('bpf/filebox.bpf.c'))

        logger.info('Loading BPF program...')
        self.bpf = builder.build()

        self._register_map_types()
        self._register_ringbufs()

        self._store_pid()

        self._bootstrap_processes()

        # TODO testing
        # Add your policy here, following the examples below
        self.add_policy('/bin/cat', '/tmp/foo', FileAccess.READ, PolicyDecision.DENY)
        self.add_policy('/bin/nvim', '/tmp/foo', FileAccess.READ|FileAccess.WRITE, PolicyDecision.ALLOW)
        self.add_policy('/usr/bin/mv', '/tmp/secret', FileAccess.WRITE|FileAccess.EXEC|FileAccess.READ, PolicyDecision.ALLOW)

    def on_tick(self) -> None:
        """
        Do a tick.
        """
        self.bpf.ringbuf_consume()

    def add_policy(self, executable: str, pathname: str, access: FileAccess, decision: PolicyDecision) -> None:
        """
        Add new policy where @executable performing @access on @pathname
        results in @decision.
        """
        key = PolicyKey()
        # Find the inode for pathname if it exists
        try:
            key.inode_key = InodeKey.from_pathname(pathname)
        except FileNotFoundError:
            logger.error(f'Inode {pathname} does not exist')
            return
        # Find the inode for executable if it exists
        try:
            key.executable_key = InodeKey.from_pathname(executable)
        except FileNotFoundError:
            logger.error(f'Executable {executable} does not exist')
            return
        try:
            policy = self.bpf.map('inode_policy')[key]
        except KeyError:
            policy = Policy()
        if decision & PolicyDecision.ALLOW:
            policy.allow |= access
        if decision & PolicyDecision.AUDIT:
            policy.audit |= access
        if decision & PolicyDecision.DENY:
            policy.deny |= access
        self.bpf.map('inode_policy')[key] = policy
        self.bpf.map('inode_enforcing')[key.inode_key] = True

    def _register_map_types(self):
        """
        Register map datatypes for the BPF program.
        """
        self.bpf.map('task_states').register_key_type(ct.c_uint32)
        self.bpf.map('task_states').register_value_type(TaskState)

        self.bpf.map('inode_policy').register_key_type(PolicyKey)
        self.bpf.map('inode_policy').register_value_type(Policy)

        self.bpf.map('inode_enforcing').register_key_type(InodeKey)
        self.bpf.map('inode_enforcing').register_value_type(ct.c_bool)

        self.bpf.map('filebox_pid_map').register_value_type(ct.c_uint32)

    def _register_ringbufs(self):
        """
        Register ringbuf callbacks for the BPF program.
        """
        @self.bpf.ringbuf_callback('on_execve_events', ExecveEvent)
        def _callback(cpu, data, size):
            # FIXME: most of this nonsense won't be necessary when we have bpf_d_path
            # If we already have our full path, stop here
            if os.path.isabs(self.executables.get(data.executable_key.flatten(), 'none')):
                return
            # Try to get the key, pathname pair from procfs
            try:
                key, exe = running_process(data.pid)
                self.executables[key.flatten()] = exe
            # If we can't fall back to comm if necessary
            except TypeError:
                if data.executable_key.flatten() in self.executables.keys():
                    return
                # Fall back to comm if we have no other choice
                self.executables[data.executable_key.flatten()] = data.comm.decode('utf-8')

        @self.bpf.ringbuf_callback('audit_inode_events', InodeAuditInfo)
        def _callback(cpu, data, size):
            decision = PolicyDecision(data.decision).names()
            access = FileAccess(data.access).names()
            executable = self.executables.get(data.executable_key.flatten(), f'[UNKNOWN {(data.executable_key.st_ino, data.executable_key.st_dev)}]')
            _file = (data.inode_key.st_ino, data.inode_key.st_dev)

            logger.audit(f'action={decision} process={data.pid} ({executable}) file={_file} access={access}')

    def _bootstrap_processes(self):
        """
        Preload running processes from procfs.
        """
        for key, exe, tid in running_processes():
            self.executables[key.flatten()] = exe
            state = TaskState()
            state.executable_key = key
            self.bpf.map('task_states')[tid] = state

    def _store_pid(self):
        """
        Store filebox's pid in a BPF map.
        """
        self.bpf.map('filebox_pid_map')[0] = os.getpid()
