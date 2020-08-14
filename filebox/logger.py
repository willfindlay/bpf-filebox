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
import logging, logging.handlers
import datetime as dt
import re

from colorama import Fore, Style

LOGGER_NAME='filebox'

class FileboxFormatter(logging.Formatter):
    """
    Formats logs.
    """
    converter=dt.datetime.fromtimestamp
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s.%03d" % (t, record.msecs)
        return s

    def format(self, record):
        record.levelname = record.levelname.lower()
        return logging.Formatter.format(self, record)

line_re = re.compile(r'(\[[^\[]*\]\s+)(\[[^\[]*\]\s+)(\[[^\[]*\])(.*)')
class FileboxColoredFormatter(FileboxFormatter):
    """
    Formats logs with color.
    """
    def color_time(self, time: str):
        return Fore.GREEN + time

    def color_logger(self, logger: str):
        return Fore.LIGHTBLACK_EX + logger

    def color_category(self, category: str):
        if 'info' in category:
            color = Fore.BLUE
        elif 'debug' in category:
            color = Fore.CYAN
        elif 'warn' in category:
            color = Fore.YELLOW
        elif 'audit' in category:
            color = Fore.LIGHTYELLOW_EX
        elif 'error' in category:
            color = Fore.RED
        else:
            color = Fore.RESET
        return color + category

    def color_log(self, line: str):
        match = line_re.match(line)
        if not match:
            raise IOError('Log message does not match pattern!')
        line = self.color_time(match[1]) + self.color_logger(match[2]) + self.color_category(match[3]) + Style.RESET_ALL + match[4]
        return line

    def format(self, record):
        formatted = FileboxFormatter.format(self, record)
        return self.color_log(formatted)

class FileboxLoggerClass(logging.getLoggerClass()):
    """
    Custom logger class that allows for the logging of audit messages.
    """
    AUDIT = logging.WARN - 5

    def __init__(self, name, level: int = logging.NOTSET):
        super().__init__(name, level)

        logging.addLevelName(FileboxLoggerClass.AUDIT, "AUDIT")

    def audit(self, msg: str, *args, **kwargs) -> None:
        """
        Write a policy message to logs.
        This should be used to inform the user about policy decisions/enforcement.
        """
        if self.isEnabledFor(FileboxLoggerClass.AUDIT):
            self._log(FileboxLoggerClass.AUDIT, msg, args, **kwargs)

logging.setLoggerClass(FileboxLoggerClass)

def init_logger(level=logging.INFO):
    """
    Initialize the filebox logger.
    """
    logger = logging.getLogger(LOGGER_NAME)

    logger.setLevel(level)

    console_handler = logging.StreamHandler()
    console_formatter = FileboxColoredFormatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(console_handler)

    #logfile_handler = logging.handlers.WatchedFileHandler()


def get_logger():
    """
    Get a copy of the filebox logger.
    """
    return logging.getLogger(LOGGER_NAME)
