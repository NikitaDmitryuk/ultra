#!/usr/bin/env python3
"""Migrate explicitly listed emergency inputs to root ownership without reading file contents."""
import argparse
import fcntl
import os
from pathlib import Path
import stat
import sys


class MigrationError(Exception):
    pass


def require(value, code):
    if not value:
        raise MigrationError(code)


def open_target(path):
    require(path.is_absolute(), 'operator_input_absolute_path_required')
    parts = path.parts[1:]
    require(parts and all(part not in ('', '.', '..') for part in parts), 'operator_input_path_invalid')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        return fd
    finally:
        os.close(parent)


def migrate(path, from_uid, apply):
    fd = open_target(path)
    held_lock = False
    try:
        info = os.fstat(fd)
        is_directory = stat.S_ISDIR(info.st_mode)
        require(is_directory or stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'operator_input_regular_single_link_or_directory_required')
        require(info.st_uid in (0, from_uid), 'operator_input_owner_mismatch')
        require(not info.st_mode & 0o022, 'operator_input_group_world_write_forbidden')
        lock_file = (path.name in ('manual-deploy.lock', 'deploy.lock') or
                     path.name.endswith('.manual-deploy.lock'))
        if lock_file:
            require(not is_directory, 'operator_lock_must_be_regular_file')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError('operator_lock_busy') from None
            held_lock = True
        mode = 0o700 if is_directory else 0o600
        print(('apply' if apply else 'dry-run') + ': ' + str(path) +
              ' owner=' + str(info.st_uid) + ' mode=' + oct(stat.S_IMODE(info.st_mode)) +
              ' -> root mode=' + oct(mode))
        if apply:
            if info.st_uid != 0:
                os.fchown(fd, 0, 0)
            os.fchmod(fd, mode)
            after = os.fstat(fd)
            require(after.st_uid == 0 and stat.S_IMODE(after.st_mode) == mode,
                    'operator_input_migration_postcondition_failed')
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', action='append', required=True, help='one exact absolute file or directory path; repeat explicitly')
    parser.add_argument('--from-uid', required=True, type=int, help='the exact prior owner UID to accept')
    parser.add_argument('--apply', action='store_true', help='apply ownership and private mode changes; default is dry-run')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'operator_input_migration_requires_root')
    require(args.from_uid > 0, 'operator_input_from_uid_invalid')
    for value in args.path:
        migrate(Path(value), args.from_uid, args.apply)


if __name__ == '__main__':
    try:
        main()
    except (MigrationError, OSError, ValueError) as error:
        print('operator-inputs: ' + (str(error) if isinstance(error, MigrationError) else 'migration_failed'), file=sys.stderr)
        sys.exit(1)
