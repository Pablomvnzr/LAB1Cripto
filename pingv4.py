#!/usr/bin/env python3
"""
pingv4.py - Envío de datos por ICMP stealth
Laboratorio 1 - Seguridad en Redes

Uso:
  sudo python3 pingv4.py "texto"              → Envía a 8.8.8.8
  sudo python3 pingv4.py "texto" 127.0.0.1   → Envía a loopback
  sudo python3 pingv4.py "texto" IP          → Envía a IP específica
"""
import sys
import os
import time
import socket
import struct
import random

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
    CUMPLE CON TODOS LOS REQUISITOS DE LA PAUTA:
    - 5 bytes 0x00 (bytes 8-12)
    - Patrón 0x10 a 0x37 COMPLETO (bytes 13-52)
    - Timestamp (bytes 0-7)
    - Carácter al FINAL del payload (NO rompe el patrón 0x10-0x37)
    - Checksum correcto
    """
    # ICMP header fields
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_checksum = 0
    
    # ================================================================
    # PAYLOAD QUE CUMPLE CON TODOS LOS REQUISITOS DE LA PAUTA
    # ESTRUCTURA:
    # [Timestamp 8 bytes] + [0x00 x5] + [0x10-0x37 COMPLETO] + [carácter al final]
    # ================================================================
    
    # 1. Timestamp (8 bytes) - como ping real
    timestamp = struct.pack('!d', time.time())
    
    # 2. 5 bytes de 0x00 (REQUISITO DE LA PAUTA)
    five_zeros = b'\x00' * 5
    
    # 3. Patrón 0x10 a 0x37 COMPLETO (REQUISITO DE LA PAUTA)
    # Esto genera: 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
    pattern = bytes([i for i in range(0x10, 0x38)])
    
    # 4. Construir payload base
    payload = bytearray()
    payload.extend(timestamp)      # 8 bytes (pos 0-7)
    payload.extend(five_zeros)     # 5 bytes (pos 8-12)
    payload.extend(pattern)        # 40 bytes (pos 13-52) 0x10-0x37 COMPLETO
    
    # 5. Elegir tamaño total del paquete (como ping real)
    total_sizes = [90, 98, 106]
    packet_size = random.choice(total_sizes)
    payload_size = packet_size - 8  # Restar header ICMP (8 bytes)
    
    # 6. Agregar el carácter AL FINAL del payload (NO rompe el patrón)
    char_byte = ord(data) if data else 0x00
    current_len = len(payload)
    
    if current_len < payload_size:
        # Agregar el carácter y luego padding
        payload.append(char_byte)
        # Rellenar el resto con padding incremental
        padding_size = payload_size - len(payload)
        if padding_size > 0:
            padding = bytes([i % 256 for i in range(padding_size)])
            payload.extend(padding)
    else:
        # Si no hay espacio, truncar (no debería pasar)
        payload = payload[:payload_size]
    
    # ================================================================
    # CONSTRUIR PAQUETE COMPLETO
    # ================================================================
    
    # Pack ICMP header (without checksum)
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, 
                              identifier, sequence)
    
    # Calculate checksum with payload
    packet = icmp_header + bytes(payload)
    icmp_checksum = calculate_checksum(packet)
    
    # Rebuild packet with correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum,
                              identifier, sequence)
    
    return icmp_header + bytes(payload), packet_size

def send_icmp_packet(dest_ip, data, sequence, identifier):
    """
    Send a single ICMP packet with realistic fields
    """
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Create realistic ICMP packet
        packet, packet_size = create_realistic_icmp_packet(data, sequence, identifier)
        
        # Send packet
        sock.sendto(packet, (dest_ip, 0))
        sock.close()
        
        return True, packet_size
    except PermissionError:
        print("\nError: Need root privileges")
        return False, 0
    except Exception as e:
        print(f"\nError: {e}")
        return False, 0

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
    print(f"Intervalo: 1 segundo entre paquetes")
    print(f"REQUISITOS CUMPLIDOS:")
    print(f"  - 5 bytes 0x00 en payload")
    print(f"  - Patrón 0x10-0x37 COMPLETO (sin romper)")
    print(f"  - Carácter al FINAL del payload")
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
    size_stats = {}
    
    for i, char in enumerate(text, 1):
        # Use sequence number (increments like real ping)
        sequence = i
        
        # Enviar el carácter
        result, packet_size = send_icmp_packet(dest_ip, char, sequence, identifier)
        
        if result:
            success_count += 1
            size_stats[packet_size] = size_stats.get(packet_size, 0) + 1
            
            # Mostrar con indicador de loopback si corresponde
            if modo == "LOOPBACK":
                print(f"  [{i:3d}] 🔄 '{char}' (0x{ord(char):02x}) | Seq: {i} | {packet_size} bytes [LOOPBACK]")
            else:
                print(f"  [{i:3d}] '{char}' (0x{ord(char):02x}) | Seq: {i} | {packet_size} bytes")
            
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
    print("✓ REQUISITOS DE PAYLOAD CUMPLIDOS:")
    print("   - 5 bytes 0x00 incluidos en el payload")
    print("   - Patrón 0x10-0x37 COMPLETO (sin romper)")
    print("   - Carácter al FINAL del payload")
    print(f"✓ Distribución de tamaños:")
    for size, count in sorted(size_stats.items()):
        print(f"   - {size} bytes: {count} paquetes")
    print("✓ Traffic mimics real ping behavior")

if __name__ == "__main__":
    main()