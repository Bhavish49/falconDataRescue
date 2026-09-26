import io
import struct
import sys

sys.path.insert(0, r"C:\MCE\backend")
from app.services import ntfs_deleted_recovery as ndr

CLUSTER = 4096
RECORD = 1024
PAYLOAD = (b"DELETED-PAYLOAD-" * 6)[:100]
INLINE = b"tiny resident payload!"


def enc_runs(runs):
    out = bytearray()
    prev = 0
    for lcn, count in runs:
        delta = lcn - prev
        out += bytes([0x11, count & 0xFF, delta & 0xFF])
        prev = lcn
    out += b"\x00"
    return bytes(out)


def resident_attr(atype, value):
    length = (24 + len(value) + 7) // 8 * 8
    hdr = struct.pack("<II", atype, length) + bytes([0, 0]) + struct.pack("<HHH", 0, 0, 0)
    hdr += struct.pack("<IH", len(value), 24) + b"\x00\x00"
    body = hdr + value
    return body + b"\x00" * (length - len(body))


def nonres_attr(atype, runs, real_size):
    run_bytes = enc_runs(runs)
    total_clusters = sum(c for _, c in runs)
    length = (72 + len(run_bytes) + 7) // 8 * 8
    hdr = struct.pack("<II", atype, length) + bytes([1, 0]) + struct.pack("<HHH", 0, 0, 0)
    hdr += struct.pack("<QQ", 0, total_clusters - 1)
    hdr += struct.pack("<HBB", 64, 0, 0)
    hdr += b"\x00" * 4
    hdr += struct.pack("<QQQ", total_clusters * CLUSTER, real_size, real_size)
    body = hdr + run_bytes
    return body + b"\x00" * (length - len(body))


def file_name_value(name):
    raw = name.encode("utf-16-le")
    val = struct.pack("<Q", 0x5000000000005)
    val += b"\x00" * 32
    val += struct.pack("<QQ", 4096, len(PAYLOAD))
    val += struct.pack("<II", 0, 0)
    val += bytes([len(name), 1])
    val += raw
    return val


def record(flags, attrs):
    body = b"".join(attrs) + struct.pack("<I", 0xFFFFFFFF)
    rec = bytearray(RECORD)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x14, 48)
    struct.pack_into("<H", rec, 0x16, flags)
    rec[48:48 + len(body)] = body
    return bytes(rec)


image = bytearray(CLUSTER * 40)

bs = bytearray(512)
bs[3:8] = b"NTFS "
struct.pack_into("<H", bs, 0x0B, 512)
bs[0x0D] = 8
struct.pack_into("<Q", bs, 0x30, 4)
struct.pack_into("<b", bs, 0x40, -10)
image[0:512] = bs

rec0 = record(1, [nonres_attr(0x80, [(4, 3)], 3 * CLUSTER)])
rec1 = record(0, [resident_attr(0x30, file_name_value("secret_notes.txt")),
                  nonres_attr(0x80, [(30, 1)], len(PAYLOAD))])
rec2 = record(0, [resident_attr(0x30, file_name_value("tiny.txt")),
                  resident_attr(0x80, INLINE)])
rec3 = record(1, [resident_attr(0x30, file_name_value("live_file.docx")),
                  nonres_attr(0x80, [(31, 1)], 500)])

image[4 * CLUSTER:4 * CLUSTER + RECORD] = rec0
image[5 * CLUSTER:5 * CLUSTER + RECORD] = rec1
image[6 * CLUSTER:6 * CLUSTER + RECORD] = rec2
image[7 * CLUSTER:7 * CLUSTER + RECORD] = rec3
image[30 * CLUSTER:30 * CLUSTER + len(PAYLOAD)] = PAYLOAD

vol = ndr.Volume(io.BytesIO(bytes(image)))
res = ndr._scan_volume(vol, 10, "TEST:")

names = [i["filename"] for i in res["items"]]
print("recovered:", names)
assert "secret_notes.txt" in names, names
assert "tiny.txt" in names, names
assert "live_file.docx" not in names, "in-use record must be skipped"
got = next(i for i in res["items"] if i["filename"] == "secret_notes.txt")
assert ndr.DELETED_STORE[got["id"]][1] == PAYLOAD, "payload mismatch"
assert got["deletion_proven"] is True
tiny = next(i for i in res["items"] if i["filename"] == "tiny.txt")
assert ndr.DELETED_STORE[tiny["id"]][1] == INLINE
print("records_scanned:", res["records_scanned"])
print("SYNTHETIC NTFS TEST PASSED")
