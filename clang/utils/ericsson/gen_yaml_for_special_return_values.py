#!/usr/bin/env python3

import re
import fileinput

# This script lists
# functions of which the return
# value is checked for negative
# (integers) or null (pointers).

# Sample input line for this script:
# /.../x.c:551:12: warning: Special Return Value:/.../x.c:551:12,parsedate,0,0


def main():
    gen_yaml()


def gen_yaml():
    print("#")
    print("# SpecialReturn metadata format 1.0\n")

    THRESHOLD = 0.85
    MIN_OCCURENCE_COUNT = 1
    p = re.compile('.*Special Return Value:(.*:[0-9]*:[0-9]*)(?: <Spelling\=(.*:[0-9]*:[0-9]*)>)?,(.*),([0,1]),([0,1])')
    nof_negative = dict()
    nof_null = dict()
    total = dict()
    for line in fileinput.input():
        m = p.match(line)
        if m:
            caller = m.group(1)
            spelling = m.group(2)
            func = m.group(3)
            ret_negative = m.group(4)
            ret_null = m.group(5)
            if spelling is not None:
                caller = spelling
            if not func in total:
                total[func] = set()
                nof_negative[func] = set()
                nof_null[func] = set()
            total[func].add(caller)
            if ret_negative == "1":
                nof_negative[func].add(caller)
            if ret_null == "1":
                nof_null[func].add(caller)

    for key in sorted(total):
        negative_ratio = len(nof_negative[key])/len(total[key])
        null_ratio = len(nof_null[key])/len(total[key])
        if (negative_ratio > THRESHOLD and \
            len(total[key]) >= MIN_OCCURENCE_COUNT):
            print("{name: " + key + ", relation: LT, value: 0}")
        if (null_ratio > THRESHOLD and \
            len(total[key]) >= MIN_OCCURENCE_COUNT):
            print("{name: " + key + ", relation: EQ, value: 0}")

if __name__ == "__main__":
    main()
