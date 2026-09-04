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
    # El payload DEBE ser EXACTAMENTE el carácter que queremos enviar
    payload = data.encode('utf-8')
    
    # Pad to typical ping payload size (48 bytes - 64 bytes)
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
    return os.getpid() & 0xFFFF

def send_ping_sequence(ip):
    """
    Send a real ping first to establish baseline (like normal ping)
    """
    print(f"Sending baseline ping to {ip}...")
    try:
        os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return True
    except:
        return False

def main():
    # ============================================================
    # DETECCIÓN DE ARGUMENTOS - IP DESTINO OPCIONAL
    # ============================================================
    
    # Caso 1: Solo texto (usa 8.8.8.8 por defecto)
    if len(sys.argv) == 2:
        text = sys.argv[1]
        dest_ip = "8.8.8.8"
        modo = "REMOTO (8.8.8.8)"
    
    # Caso 2: Texto + IP destino
    elif len(sys.argv) == 3:
        text = sys.argv[1]
        dest_ip = sys.argv[2]
        # Detectar si es loopback
        if dest_ip == "127.0.0.1" or dest_ip == "localhost":
            modo = "LOOPBACK"
        else:
            modo = f"REMOTO ({dest_ip})"
    
    # Caso 3: Argumentos incorrectos
    else:
        print("\n" + "="*60)
        print("ICMP Stealth Sender - Laboratorio 1")
        print("="*60)
        print("\nUSO:")
        print('  sudo python3 pingv4.py "texto"              → Envía a 8.8.8.8')
        print('  sudo python3 pingv4.py "texto" 127.0.0.1   → Envía a loopback')
        print('  sudo python3 pingv4.py "texto" IP          → Envía a IP específica')
        print("\nEJEMPLOS:")
        print('  sudo python3 pingv4.py "larycxojxrji h bnovjajrji nw anmcb"')
        print('  sudo python3 pingv4.py "test" 127.0.0.1')
        print("="*60)
        sys.exit(1)
    
    # ============================================================
    # CONFIGURACIÓN
    # ============================================================
    
    # Generate consistent identifier for all packets (like real ping)
    identifier = generate_identifier()
    
    print(f"\n{'='*60}")
    print(f"ICMP Stealth Sender - Laboratorio 1")
    print(f"{'='*60}")
    print(f"Texto a enviar: '{text}'")
    print(f"Longitud: {len(text)} caracteres")
    print(f"IP destino: {dest_ip}")
    print(f"Modo: {modo}")
    print(f"ICMP Identifier: 0x{identifier:04x} (PID: {identifier})")
    print(f"Intervalo: 1 segundo entre paquetes (REQUISITO LABORATORIO)")
    print(f"{'='*60}\n")
    
    # Send a real ping first to establish baseline
    print("\n=== Establishing normal traffic pattern ===")
    send_ping_sequence(dest_ip)
    time.sleep(0.5)
    
    print(f"\n=== Sending {len(text)} characters via ICMP ===")
    print("Cada paquete se envía con intervalo de 1 segundo\n")
    
    # Send each character via ICMP
    total_chars = len(text)
    success_count = 0
    
    for i, char in enumerate(text, 1):
        # Use sequence number (increments like real ping)
        sequence = i
        
        # Enviar el carácter
        if send_icmp_packet(dest_ip, char, sequence, identifier):
            success_count += 1
            # Mostrar con indicador de loopback si corresponde
            if modo == "LOOPBACK":
                print(f"  [{i:3d}] 🔄 '{char}' (0x{ord(char):02x}) enviado | Seq: {i} [LOOPBACK]")
            else:
                print(f"  [{i:3d}] '{char}' (0x{ord(char):02x}) enviado | Seq: {i}")
            
            # ESPERA DE EXACTAMENTE 1 SEGUNDO
            if i < total_chars:
                time.sleep(1.0)
        else:
            print(f"\nFailed to send packet {i}")
            sys.exit(1)
    
    # Send a real ping after to complete the pattern
    print("\n=== Completing traffic pattern ===")
    time.sleep(0.5)
    send_ping_sequence(dest_ip)
    
    print(f"\n✓ Successfully sent {success_count}/{total_chars} characters")
    print(f"✓ Intervalo de 1 segundo entre paquetes")
    print(f"✓ IP destino: {dest_ip}")
    if modo == "LOOPBACK":
        print("✓ Modo LOOPBACK activado (127.0.0.1)")
    print("✓ Traffic mimics real ping behavior")

if __name__ == "__main__":
    main()