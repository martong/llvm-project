#!/usr/bin/env python3

import re
import fileinput

# This script lists
# functions of which the return
# value is mostly checked.

# Sample input line for this script:
# /.../x.c:551:12: warning: Return Value Check:/.../x.c:551:12,parsedate,0


def main():
    gen_yaml()


def gen_yaml():
    print("#")
    print("# UncheckedReturn metadata format 1.0\n")

    THRESHOLD = 0.85
    MIN_OCCURENCE_COUNT = 1
    p = re.compile('.*Return Value Check:(.*:[0-9]*:[0-9]*)(?: <Spelling\=(.*:[0-9]*:[0-9]*)>)?,(.*),([0,1])')
    nof_unchecked = dict()
    total = dict()
    for line in fileinput.input():
        m = p.match(line)
        if m:
            caller = m.group(1)
            spelling = m.group(2)
            func = m.group(3)
            unchecked = m.group(4)
            if spelling is not None:
                caller = spelling
            if not func in total:
                total[func] = set()
                nof_unchecked[func] = set()
            total[func].add(caller)
            if unchecked == "1":
                nof_unchecked[func].add(caller)

    for key in sorted(total):
        checked_ratio = 1 - len(nof_unchecked[key])/len(total[key])
        if (checked_ratio > THRESHOLD and \
            len(total[key]) >= MIN_OCCURENCE_COUNT):
            print("- " + key)

if __name__ == "__main__":
    main()
