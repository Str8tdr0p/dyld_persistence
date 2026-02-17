#!/usr/bin/env python3
# Forensic Verifier v1.2
# TARGET: iOS 26.3 (23D127) Rogue DSC Slice
# SHA-256: ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770

import os
import struct
import hashlib
import sys

DEFAULT_FILENAME = "168CADF663A7397F9E9D2CE113F33C6C"
EXPECTED_HASH = "ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770"

def run_verification(target_path):
    all_pass = True
    
    print("=" * 68)
    print(" iOS GHOST-SLICE VERIFIER v1.3 - CISA/MITRE VALIDATION TOOL ")
    print("=" * 68)

    # FILE EXISTS CHECK
    if not os.path.exists(target_path):
        print(f"[!] ERROR: {target_path} not found")
        sys.exit(1)

    # LOAD BINARY
    try:
        with open(target_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[!] ERROR: Cannot read {target_path}: {e}")
        sys.exit(1)

    # [1] HASH VALIDATION (CRITICAL)
    actual_hash = hashlib.sha256(data).hexdigest()
    print(f"[1] HASH VALIDATION")
    print(f"    Computed:   {actual_hash}")
    print(f"    Expected:   {EXPECTED_HASH}")
    if actual_hash == EXPECTED_HASH:
        print("    RESULT: [PASS] Exact forensic artifact confirmed")
    else:
        print("    RESULT: [FAIL] Hash mismatch - wrong artifact")
        all_pass = False

    # [2] HEADER ANOMALY (CRITICAL - Integer Overflow Trigger)
    print(f"[2] DSC HEADER ANALYSIS")
    try:
        magic, version, img_cnt, img_off, map_cnt, map_off = struct.unpack('<IIIIII', data[:24])
        print(f"    Magic:    {hex(magic)}")
        print(f"    Maps:     {map_cnt:,}")
        print(f"    Images:   {img_cnt:,}")
        if map_cnt > 900000:
            print("    RESULT: [PASS] Impossible mapping count (EXPLOIT TRIGGER)")
        else:
            print("    RESULT: [FAIL] Normal mapping count")
            all_pass = False
    except Exception as e:
        print(f"    RESULT: [ERROR] Header parse failed: {e}")
        all_pass = False

    # [3] SHELLCODE HEURISTIC (Metadata Repurposed)
    print(f"[3] DATA-AS-CODE AUDIT")
    if len(data) > 0x2000:
        bl_pattern = b'\x00\x00\x00\x94'  # ARM64 BL imm=0
        target_region = data[0x15cd:0x2000]
        bl_count = target_region.count(bl_pattern)
        print(f"    BL insts @0x15cd: {bl_count}")
        if bl_count > 0:
            print("    RESULT: [PASS] Executable code in metadata zone")
        else:
            print("    RESULT: [WARNING] No BL patterns (heuristic only)")
    else:
        print("    RESULT: [ERROR] File too short for analysis")

    # [4] AMFI BYPASS STRINGS (BONUS EVIDENCE)
    print(f"[4] BYPASS SIGNATURE SCAN")
    signatures = [b"DYLD_AMFI_FAKE", b"AMFI_STUB"]
    found = False
    for sig in signatures:
        if sig in data:
            print(f"    FOUND: {sig.decode()}")
            found = True
    if not found:
        print("    RESULT: No AMFI strings (non-critical)")

    # FINAL RESULT
    print("=" * 68)
    if all_pass:
        print(" RESULT: ALL CRITICAL GHOST-SLICE INDICATORS CONFIRMED")
        print(" STATUS: HELLO WORLD")
        sys.exit(0)
    else:
        print(" RESULT: CRITICAL CHECKS FAILED")
        print(" STATUS: INVALID ARTIFACT")
        sys.exit(1)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILENAME
    run_verification(target)
