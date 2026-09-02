#!/usr/bin/env python3
import sys
import os
import time
import socket
import struct
import random
import binascii

def calculate_checksum(packet):
    """
    Calculate ICMP checksum (same as real ping)
    """
    if len(packet) % 2 != 0:
        packet += b'\x00'
    
    checksum = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF

def create_realistic_icmp_packet(data, sequence, identifier):
    """
    Creates an ICMP Echo Request packet that looks exactly like real ping
    """
    # ICMP header fields (same as standard ping)
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_checksum = 0
    
    # Pack ICMP header (without checksum)
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, 
                              identifier, sequence)
    
    # Add payload with realistic padding
    # Real ping uses data like "abcdefghijklmnopqrstuvwabcdefghi"
    # We'll use our character but add padding to match standard ping size
    payload = data.encode('utf-8')
    
    # Pad to typical ping payload size (48 bytes - 64 bytes)
    # This makes packets look like standard ping
    padding_size = random.choice([48, 56, 64]) - len(payload)
    if padding_size > 0:
        # Add realistic padding with incremental bytes
        padding = bytes([i % 256 for i in range(padding_size)])
        payload += padding
    
    # Calculate checksum with payload
    packet = icmp_header + payload
    icmp_checksum = calculate_checksum(packet)
    
    # Rebuild packet with correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum,
                              identifier, sequence)
    
    return icmp_header + payload

def send_icmp_packet(dest_ip, data, sequence, identifier):
    """
    Send a single ICMP packet with realistic fields
    """
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Create realistic ICMP packet
        packet = create_realistic_icmp_packet(data, sequence, identifier)
        
        # Send packet
        sock.sendto(packet, (dest_ip, 0))
        sock.close()
        
        return True
    except PermissionError:
        print("\nError: Need root privileges")
        return False
    except Exception as e:
        print(f"\nError: {e}")
        return False

def generate_identifier():
    """
    Generate a realistic identifier like real ping
    """
    # Real ping uses process ID or random values
    return os.getpid() & 0xFFFF

def generate_realistic_delay():
    """
    Generate realistic delays between packets
    Real ping has consistent but slightly varying delays
    """
    # Base delay around 0.1-0.3 seconds with slight variation
    return random.uniform(0.08, 0.15)

def send_ping_sequence(ip):
    """
    Send a real ping first to establish baseline (like normal ping)
    """
    print(f"Sending baseline ping to {ip}...")
    try:
        # Use system ping to establish normal traffic pattern
        os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return True
    except:
        return False

def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: sudo python3 pingv4.py \"text to send\"")
        print("Example: sudo python3 pingv4.py \"larycxojxrji h bnovjajrji nw anmcb\"")
        sys.exit(1)
    
    # Get text to send
    text = sys.argv[1]
    
    # Destination IP (make it configurable)
    dest_ip = "8.8.8.8"  # Google DNS
    
    # Generate consistent identifier for all packets (like real ping)
    identifier = generate_identifier()
    
    # Send a real ping first to establish baseline
    print("\n=== Establishing normal traffic pattern ===")
    send_ping_sequence(dest_ip)
    time.sleep(0.5)
    
    print(f"\n=== Sending {len(text)} characters via ICMP ===")
    print("Packets mimic real ping behavior\n")
    
    # Send each character via ICMP
    total_chars = len(text)
    success_count = 0
    
    for i, char in enumerate(text, 1):
        # Use sequence number (increments like real ping)
        sequence = i
        
        # Send character in ICMP data field with realistic packet
        if send_icmp_packet(dest_ip, char, sequence, identifier):
            success_count += 1
            print(f".\nSent {i} packets.")
            
            # Random but realistic delay
            time.sleep(generate_realistic_delay())
        else:
            print(f"\nFailed to send packet {i}")
            sys.exit(1)
    
    # Send a real ping after to complete the pattern
    print("\n=== Completing traffic pattern ===")
    time.sleep(0.5)
    send_ping_sequence(dest_ip)
    
    print(f"\n✓ Successfully sent {success_count}/{total_chars} characters")
    print("✓ Traffic mimics real ping behavior")

if __name__ == "__main__":
    main()


