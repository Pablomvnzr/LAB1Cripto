#!/usr/bin/env python3
"""
readv2_scapy.py – ICMP Caesar-cipher reader using Scapy (FIXED)
Properly detects sender ID by looking for the most common ID
Shows ALL 26 Caesar shift combinations in order (0-25)
"""

import sys
import os
import time
from collections import defaultdict, Counter

try:
    from scapy.all import sniff, ICMP, IP, Raw, Ether
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip3 install scapy")
    sys.exit(1)

# ── ANSI colour codes ─────────────────────────────────────────────────────────
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RED    = '\033[91m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ── Letter-frequency tables ──────────────────────────────────────────────────
ENGLISH_FREQ = {
    'a':  8.17, 'b':  1.29, 'c':  2.78, 'd':  4.25, 'e': 12.70,
    'f':  2.23, 'g':  2.02, 'h':  6.09, 'i':  6.97, 'j':  0.15,
    'k':  0.77, 'l':  4.03, 'm':  2.41, 'n':  6.75, 'o':  7.51,
    'p':  1.93, 'q':  0.10, 'r':  5.99, 's':  6.33, 't':  9.06,
    'u':  2.76, 'v':  0.98, 'w':  2.36, 'x':  0.15, 'y':  1.97,
    'z':  0.07,
}

SPANISH_FREQ = {
    'a': 12.53, 'b':  1.42, 'c':  4.68, 'd':  5.86, 'e': 13.72,
    'f':  0.69, 'g':  1.01, 'h':  0.70, 'i':  6.25, 'j':  0.44,
    'k':  0.01, 'l':  4.97, 'm':  3.15, 'n':  6.71, 'o':  8.68,
    'p':  2.51, 'q':  0.88, 'r':  6.87, 's':  7.98, 't':  4.63,
    'u':  3.93, 'v':  0.90, 'w':  0.01, 'x':  0.22, 'y':  0.90,
    'z':  0.52,
}

# ── Caesar helpers ────────────────────────────────────────────────────────────

def caesar_decrypt(text: str, shift: int) -> str:
    """Shift every alphabetic character back by *shift* positions (mod 26)."""
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)

def score_text(text: str) -> float:
    """Frequency-correlation score against English and Spanish tables."""
    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return 0.0

    n = len(letters)
    obs = defaultdict(float)
    for c in letters:
        obs[c] += 1.0 / n

    score_en = sum(obs[c] * ENGLISH_FREQ.get(c, 0.0) for c in obs)
    score_es = sum(obs[c] * SPANISH_FREQ.get(c, 0.0) for c in obs)
    return max(score_en, score_es)

def all_shifts(ciphertext: str) -> list:
    """Return a list of (shift, plaintext, score) for all 26 shifts in order."""
    results = []
    for shift in range(26):
        pt = caesar_decrypt(ciphertext, shift)
        results.append((shift, pt, score_text(pt)))
    return results

def find_best_shift(results: list) -> int:
    """Find the shift with the highest score."""
    best_score = -1
    best_shift = 0
    for shift, plaintext, score in results:
        if score > best_score:
            best_score = score
            best_shift = shift
    return best_shift

# ── Packet capture with Scapy ─────────────────────────────────────────────────

class ICMPCapture:
    def __init__(self):
        self.captured = {}
        self.sender_id = None
        self.packet_count = 0
        self.start_time = time.time()
        self.id_counts = Counter()  # Track all IDs seen
        self.char_packets = []  # Store packets with characters for later analysis
        
    def packet_handler(self, packet):
        """Handle each captured packet."""
        self.packet_count += 1
        
        # Check if it's an ICMP Echo Request with payload
        if not (packet.haslayer(ICMP) and packet.haslayer(Raw)):
            return
            
        icmp = packet[ICMP]
        
        # Only Echo Request (type 8)
        if icmp.type != 8:
            return
            
        # Get the payload (first byte is our character)
        raw_data = packet[Raw].load
        if len(raw_data) < 1:
            return
            
        try:
            char = raw_data[:1].decode('utf-8', errors='ignore')
            if not char.isprintable():
                return
        except:
            return
            
        # Get ICMP identifier and sequence
        ident = icmp.id
        seq = icmp.seq
        
        # Track this ID
        self.id_counts[ident] += 1
        
        # Store the character with its ID for later filtering
        self.char_packets.append((ident, seq, char))
        
        # Debug first few packets
        if self.packet_count <= 10:
            print(f"[DEBUG] Packet {self.packet_count}: id=0x{ident:04x}, seq={seq}, char='{char}'")
        
        # If we have a sender ID set, filter and store
        if self.sender_id is not None and ident == self.sender_id:
            if seq not in self.captured:
                self.captured[seq] = char
                print(f"[+] Seq {seq:3d} -> '{char}' (total: {len(self.captured)})")

def capture_packets(timeout: int = 60) -> dict:
    """
    Capture ICMP Echo Request packets using Scapy.
    """
    print(f"{CYAN}[*] Starting packet capture with Scapy…{RESET}")
    print(f"[*] Listening for ICMP Echo Requests (timeout={timeout}s).")
    print(f"[*] Will auto-detect sender after collection\n")
    
    # Create capture instance
    capture = ICMPCapture()
    
    try:
        # Sniff for ICMP packets
        sniff(
            filter="icmp and icmp[icmptype]=8",  # Only Echo Requests
            prn=capture.packet_handler,
            timeout=timeout,
            store=False
        )
        
        print(f"\n[*] Capture completed (timeout={timeout}s)")
        
        # Now analyze which ID has the most packets with printable chars
        if capture.char_packets:
            # Count IDs from packets with printable characters
            id_counter = Counter()
            for ident, seq, char in capture.char_packets:
                id_counter[ident] += 1
            
            print(f"\n[*] Sender IDs detected: {len(id_counter)}")
            for ident, count in id_counter.most_common(3):
                print(f"    ID 0x{ident:04x}: {count} packets")
            
            # Pick the ID with the most packets (likely our sender)
            if id_counter:
                capture.sender_id = id_counter.most_common(1)[0][0]
                print(f"\n[+] {BOLD}Selected sender ID: 0x{capture.sender_id:04x}{RESET} ({id_counter[capture.sender_id]} packets)")
                
                # Now reprocess all packets for this ID
                for ident, seq, char in capture.char_packets:
                    if ident == capture.sender_id and seq not in capture.captured:
                        capture.captured[seq] = char
                        print(f"    Seq {seq:3d} -> '{char}'")
        
    except KeyboardInterrupt:
        print(f"\n[*] Capture stopped by user.")
    except Exception as e:
        print(f"\n[!] Error during capture: {e}")
        import traceback
        traceback.print_exc()
    
    return capture.captured

def reconstruct(packets: dict) -> str:
    """Re-order captured characters by ICMP sequence number."""
    if not packets:
        return ""
    return ''.join(packets[s] for s in sorted(packets))

# ── Display ───────────────────────────────────────────────────────────────────

def display_results(ciphertext: str, results: list) -> None:
    """Display ALL 26 Caesar shift results in order (0-25)."""
    W = 80
    
    # Find the best shift
    best_shift = find_best_shift(results)
    
    print(f"\n{'═' * W}")
    print(f"  Reconstructed text : {BOLD}{ciphertext}{RESET}")
    print(f"  Length              : {len(ciphertext)} characters")
    print(f"{'═' * W}")

    print(f"\n  {BOLD}ALL 26 Caesar shifts (ordered by shift 0-25):{RESET}")
    print(f"  {'─' * (W - 4)}")
    print(f"  {'Shift':>5}   {'Score':>8}   Plaintext")
    print(f"  {'─' * (W - 4)}")

    # Show ALL 26 shifts in order
    for shift, plaintext, score in results:
        line = f"  {shift:>5}   {score:>8.4f}   {plaintext}"
        
        # Only highlight the BEST match in green
        if shift == best_shift:
            print(f"{GREEN}{BOLD}{line}   ◄  BEST MATCH{RESET}")
        else:
            print(f"{DIM}{line}{RESET}")

    print(f"  {'─' * (W - 4)}")

    # Show summary
    best_shift, best_plain, best_score = results[best_shift]
    
    print(f"\n  {BOLD}Best match:{RESET}")
    print(f"  {GREEN}{BOLD}  Shift   : {best_shift}{RESET}")
    print(f"  {GREEN}{BOLD}  Message : {best_plain}{RESET}")
    print(f"  {GREEN}{BOLD}  Score   : {best_score:.4f}{RESET}")
    print(f"\n  {DIM}Score = frequency-correlation with English/Spanish letter tables{RESET}\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner = (
        f"{BOLD}{CYAN}\n"
        f"  ┌──────────────────────────────────────────────────┐\n"
        f"  │  ICMP Caesar-cipher reader  –  Scapy version     │\n"
        f"  │  Auto-detects sender ID from packet patterns     │\n"
        f"  │  Shows ALL 26 Caesar shifts (0-25)              │\n"
        f"  └──────────────────────────────────────────────────┘\n"
        f"{RESET}"
    )
    print(banner)

    timeout = 60
    direct_txt = None

    args = sys.argv[1:]
    if args:
        if args[0] == '--text':
            if len(args) < 2:
                print("Usage: python3 readv2_scapy.py --text \"ciphertext\"")
                sys.exit(1)
            direct_txt = args[1]
        else:
            try:
                timeout = int(args[0])
            except ValueError:
                print("Usage: sudo python3 readv2_scapy.py [timeout_seconds]")
                print("       python3 readv2_scapy.py --text \"ciphertext\"")
                sys.exit(1)

    if direct_txt is not None:
        ciphertext = direct_txt
        print(f"[*] Analysing provided text: '{ciphertext}'\n")
    else:
        packets = capture_packets(timeout)
        
        if not packets:
            print(f"\n{RED}[!] No packets captured.{RESET}")
            print(f"\n{YELLOW}Troubleshooting:{RESET}")
            print(f"  1. Make sure pingv4.py is running with sudo")
            print(f"  2. Check: sudo tcpdump -i en0 icmp")
            print(f"  3. Try: sudo python3 readv2_scapy.py 60")
            sys.exit(1)

        ciphertext = reconstruct(packets)
        print(f"\n[+] Reconstructed ciphertext: '{ciphertext}'  ({len(ciphertext)} chars)")

    if not any(c.isalpha() for c in ciphertext):
        print(f"{RED}[!] No alphabetic characters found – nothing to decrypt.{RESET}")
        sys.exit(1)

    results = all_shifts(ciphertext)
    display_results(ciphertext, results)

if __name__ == "__main__":
    main()