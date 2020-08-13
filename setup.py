#!/usr/bin/env python3

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

import os, sys
import re
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

version = '0.0.1'

setup(
    name='filebox',
    version=version,
    description='A BPF security daemon that enforces access control on inodes.',
    author='William Findlay',
    author_email='william@williamfindlay.com',
    url='https://github.com/willfindlay/bpf-filebox',
    packages=['filebox'],
    #scripts=['bin/fileboxd', 'bin/fileboxctl'],
    include_package_data=True,
    package_data={'': ['filebox/bpf/*']},
)