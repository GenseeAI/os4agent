#!/usr/bin/env python3
import io
import os
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

from pycriu.images import images, pb  # noqa: E402


def encode(*messages):
    output = io.BytesIO()
    for message in messages:
        payload = message.SerializeToString()
        output.write(struct.pack('i', len(payload)))
        output.write(payload)
    return output.getvalue()


def task(message, realpid, localpid, uid):
    message.realpid = realpid
    message.ppid = 0
    message.pgid = localpid
    message.sid = localpid
    message.nsid = 7
    message.localpid = localpid
    message.uid = uid


def main():
    handler = images.handlers['PSTREE']

    old_first = pb.pstree_entry()
    task(old_first, 1001, 1, 11)
    old_second = pb.pstree_entry()
    task(old_second, 1002, 2, 12)
    old_blob = encode(old_first, old_second)
    old_entries = handler.loads(old_blob)
    assert [entry['realpid'] for entry in old_entries] == [1001, 1002]
    assert handler.loads(handler.dumps(old_entries)) == old_entries
    assert handler.count(io.BytesIO(old_blob)) == 2

    current = pb.pstree_file_entry()
    ns_max = current.ns_max_pids.add()
    ns_max.ns_id = 7
    ns_max.pid_max = 2
    task(current.tree.add(), 1001, 1, 11)
    task(current.tree.add(), 1002, 2, 12)
    current_blob = encode(current)
    current_entries = handler.loads(current_blob)
    assert len(current_entries) == 1
    assert [entry['realpid'] for entry in current_entries[0]['tree']] == [1001, 1002]
    assert handler.loads(handler.dumps(current_entries)) == current_entries
    assert handler.count(io.BytesIO(current_blob)) == 1

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
