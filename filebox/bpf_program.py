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

from pybpf import BPFObjectBuilder

from filebox.utils import module_path

class BPFProgram:
    def __init__(self):
        self.bpf = None

    def load_bpf(self):
        assert self.bpf is None

        builder = BPFObjectBuilder()
        builder.generate_skeleton(module_path('bpf/filebox.bpf.c'))
        # TODO: add production mode that just loads the shared object
        self.bpf = builder.build()
