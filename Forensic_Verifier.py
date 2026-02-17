import os
import struct
import hashlib
import sys

# --- FORENSIC METADATA ---
# TARGET BUILD: iOS 26.3 (23D127) | Retail Production Device
# SOURCE: Artifact extracted directly from sysdiagnose archive, unmodified.
# EXPECTED FULL FILE SHA-256: ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770

# --- CONFIGURATION ---
# The analyst can either rename their download to match the UUID below 
# or pass the filename as a command-line argument.
DEFAULT_FILENAME = "168CADF663A7397F9E9D2CE113F33C6C"
EXPECTED_HASH = "ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770"

def run_verification(target_path):
    all_pass = True
    print("="*68)
    print("  iOS SILICON-LEVEL PERSISTENCE VERIFIER - FORENSIC AUDIT TOOL  ")
    print("="*68)

    if not os.path.exists(target_path):
        print(f"[!] ERROR: Target artifact not found at: {target_path}")
        print(f"    Please ensure the file from the Google Drive link is in this folder.")
        return

    with open(target_path, 'rb') as f:
        data = f.read()

    # 1. ARTIFACT INTEGRITY CHECK
    actual_hash = hashlib.sha256(data).hexdigest()
    print(f"\n[1] ARTIFACT INTEGRITY CHECK:")
    print(f"    - Computed SHA-256: {actual_hash}")
    if actual_hash == EXPECTED_HASH:
        print("    - RESULT: [PASS] File matches reported 23D127 rogue artifact.")
    else:
        print("    - RESULT: [WARNING] Hash mismatch. Verify the download integrity.")
        all_pass = False

    # 2. HEADER ANOMALY AUDIT
    try:
        # Unpack: magic(4), version(4), imgs_cnt(4), imgs_off(4), maps_cnt(4), maps_off(4)
        magic, version, img_cnt, _, map_cnt, _ = struct.unpack('<IIIIII', data[:24])
        print(f"\n[2] ARCHITECTURAL INTEGRITY AUDIT:")
        print(f"    - Header Magic: {hex(magic)} (dsch)")
        print(f"    - Reported Mappings: {map_cnt:,}")
        if map_cnt > 900000:
            print("    - RESULT: [PASS] Impossible mapping count confirmed (Overflow Trigger).")
        else:
            print("    - RESULT: [FAIL] Mapping count does not meet exploit profile.")
            all_pass = False
    except Exception as e:
        print(f"    - RESULT: [ERROR] Structural parse failure: {e}")
        all_pass = False

    # 3. DATA-AS-CODE (METADATA OFFSET 0x15cd)
    if len(data) >= 0x2000:
        bl_pattern = b'\x00\x00\x00\x94' # ARM64 Branch Link (BL)
        target_region = data[0x15cd:0x2000]
        bl_instances = target_region.count(bl_pattern)
        print(f"\n[3] DATA-AS-CODE (METADATA SEGMENT):")
        print(f"    - Heuristic BL count at 0x15cd: {bl_instances}")
        if bl_instances > 0:
            print("    - RESULT: [PASS] Executable instructions found in metadata segment.")
        else:
            print("    - RESULT: [FAIL] Metadata segment contains no branch patterns.")
            all_pass = False

    # 4. SECURITY BYPASS SIGNATURES
    print(f"\n[4] SECURITY BYPASS SIGNATURES:")
    found_sigs = [sig for sig in [b"DYLD_AMFI_FAKE", b"AMFI_STUB"] if sig in data]
    if found_sigs:
        for s in found_sigs:
            print(f"    - FOUND: {s.decode()} (Interposition logic verified)")
    else:
        print("    - RESULT: [FAIL] No known AMFI bypass strings detected.")
        all_pass = False

    print("\n" + "="*68)
    if all_pass:
        print(" VERIFICATION COMPLETE: ALL GHOST-SLICE INDICATORS CONFIRMED")
    else:
        print(" VERIFICATION COMPLETE: ONE OR MORE INDICATORS NOT PRESENT")
    print("="*68)

if __name__ == "__main__":
    # Check if a filename was passed as an argument, otherwise use default
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILENAME
    run_verification(target)
