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
import sys
import time

from filebox import defs
from filebox.bpf_program import BPFProgram
from filebox.daemon_mixin import DaemonMixin
from filebox.logger import get_logger, init_logger

logger = get_logger()

class Fileboxd(DaemonMixin):
    def __init__(self):
        self.bpf_program = BPFProgram()

    def loop_forever(self):
        logger.info('Loading BPF program...')
        self.bpf_program.load_bpf()

        logger.info('Started monitoring the system')
        while 1:
            self.bpf_program.on_tick()
            time.sleep(defs.TICKSLEEP)

def main(sys_args=sys.argv[1:]):
    init_logger()

    daemon = Fileboxd()
    daemon.loop_forever()
