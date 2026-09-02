#!/usr/bin/env python3
"""
readv2.py – ICMP Caesar-cipher reader
Detects sender ID and shows ALL 26 Caesar shifts
Improved with Spanish dictionary for better accuracy
"""

import sys
import time
import re
from collections import defaultdict, Counter

try:
    from scapy.all import sniff, ICMP, Raw
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

# ── Colores ANSI ──────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
CYAN   = '\033[96m'
RED    = '\033[91m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ── Diccionario de palabras comunes en español ──────────────────────────────
SPANISH_WORDS = {
    'a', 'ante', 'bajo', 'con', 'contra', 'de', 'desde', 'durante', 'en', 
    'entre', 'hacia', 'hasta', 'mediante', 'para', 'por', 'según', 'sin', 
    'sobre', 'tras', 'y', 'o', 'ni', 'que', 'quien', 'como', 'cuando',
    'donde', 'mientras', 'aunque', 'porque', 'pues', 'si', 'sino', 'ya',
    'casa', 'perro', 'gato', 'agua', 'sol', 'luna', 'cielo', 'tierra',
    'hombre', 'mujer', 'niño', 'familia', 'amigo', 'vida', 'tiempo',
    'trabajo', 'escuela', 'universidad', 'profesor', 'estudiante',
    'computadora', 'programa', 'codigo', 'cifrado', 'seguridad',
    'redes', 'informatica', 'clase', 'examen', 'tarea', 'libro',
    'pagina', 'ciber', 'correo', 'mensaje', 'texto', 'archivo',
    'hola', 'mundo', 'bueno', 'malo', 'grande', 'pequeño', 'nuevo',
    'viejo', 'rápido', 'lento', 'fácil', 'difícil', 'claro', 'oscuro',
    'alto', 'bajo', 'cerca', 'lejos', 'antes', 'después', 'pronto',
    'tarde', 'noche', 'día', 'semana', 'mes', 'año', 'hoy', 'mañana',
    'ayer', 'siempre', 'nunca', 'algo', 'todo', 'nada', 'mucho', 'poco',
    'cual', 'quien', 'cuyo', 'donde', 'como', 'cuanto', 'mas', 'menos',
    'tres', 'cinco', 'diez', 'cien', 'mil', 'primero', 'segundo',
    'tercero', 'ultimo', 'mismo', 'propio', 'otro', 'cada', 'solo',
    'vamos', 'vamonos', 'sigue', 'adelante', 'alto', 'basta', 'silencio',
    'atencion', 'cuidado', 'peligro', 'emergencia', 'ayuda', 'socorro',
    'si', 'no', 'tal', 'vez', 'tener', 'hacer', 'decir', 'ver', 'poder',
    'saber', 'ser', 'estar', 'ir', 'venir', 'dar', 'tomar', 'llevar',
    'dejar', 'mirar', 'escuchar', 'hablar', 'preguntar', 'responder',
    'entrar', 'salir', 'subir', 'bajar', 'correr', 'caminar', 'saltar'
}

# ── Letter-frequency tables ──────────────────────────────────────────────────
ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.29, 'c': 2.78, 'd': 4.25, 'e': 12.70,
    'f': 2.23, 'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15,
    'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75, 'o': 7.51,
    'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06,
    'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97,
    'z': 0.07,
}

SPANISH_FREQ = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.72,
    'f': 0.69, 'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44,
    'k': 0.01, 'l': 4.97, 'm': 3.15, 'n': 6.71, 'o': 8.68,
    'p': 2.51, 'q': 0.88, 'r': 6.87, 's': 7.98, 't': 4.63,
    'u': 3.93, 'v': 0.90, 'w': 0.01, 'x': 0.22, 'y': 0.90,
    'z': 0.52,
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
    """
    Enhanced scoring: frequency analysis + dictionary bonus
    """
    text_lower = text.lower()
    letters = [c for c in text_lower if c.isalpha()]
    
    if not letters:
        return 0.0
    
    # ── Frequency analysis ──────────────────────────────────────────────
    n = len(letters)
    obs = defaultdict(float)
    for c in letters:
        obs[c] += 1.0 / n
    
    score_en = sum(obs[c] * ENGLISH_FREQ.get(c, 0.0) for c in obs)
    score_es = sum(obs[c] * SPANISH_FREQ.get(c, 0.0) for c in obs)
    freq_score = max(score_en, score_es)
    
    # ── Dictionary bonus ─────────────────────────────────────────────────
    dictionary_bonus = 0.0
    
    # Extraer palabras (solo letras)
    words = re.findall(r'[a-záéíóúüñ]+', text_lower)
    
    if words:
        # Contar palabras que están en el diccionario
        common_count = sum(1 for w in words if w in SPANISH_WORDS)
        total_words = len(words)
        
        if total_words > 0:
            # Bonus basado en el porcentaje de palabras conocidas
            word_ratio = common_count / total_words
            
            # Más bonus si hay más de 2 palabras
            if total_words >= 3:
                dictionary_bonus += word_ratio * 3.0  # Hasta 3 puntos extra
            elif total_words >= 2:
                dictionary_bonus += word_ratio * 2.0  # Hasta 2 puntos extra
            else:
                dictionary_bonus += word_ratio * 1.0  # Hasta 1 punto extra
            
            # Bonus extra si una palabra larga coincide (>5 letras)
            for w in words:
                if len(w) >= 5 and w in SPANISH_WORDS:
                    dictionary_bonus += 0.5
                    break
    
    # ── Estructura bonus ─────────────────────────────────────────────────
    structure_bonus = 0.0
    
    # Bonus por tener espacios (oración)
    if ' ' in text:
        word_count = len(text.split())
        if word_count >= 3:
            structure_bonus += 0.5
        if word_count >= 5:
            structure_bonus += 0.5
    
    # Bonus por vocales (lenguaje natural)
    vowel_count = sum(1 for c in text_lower if c in 'aeiouáéíóúü')
    vowel_ratio = vowel_count / len(letters) if letters else 0
    if vowel_ratio > 0.3:
        structure_bonus += 0.3
    if vowel_ratio > 0.4:
        structure_bonus += 0.3
    
    # Bonus por tener letras comunes
    common_letters = 'aeioulnrts'
    common_ratio = sum(1 for c in text_lower if c in common_letters) / len(letters) if letters else 0
    if common_ratio > 0.6:
        structure_bonus += 0.3
    
    total_score = freq_score + dictionary_bonus + structure_bonus
    
    return total_score

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
        self.id_counts = Counter()
        self.char_packets = []
        
    def packet_handler(self, packet):
        self.packet_count += 1
        
        if not (packet.haslayer(ICMP) and packet.haslayer(Raw)):
            return
            
        icmp = packet[ICMP]
        if icmp.type != 8:
            return
            
        raw_data = packet[Raw].load
        if len(raw_data) < 1:
            return
            
        # El primer byte es nuestro carácter
        char_byte = raw_data[0]
        
        # Verificar que sea imprimible
        if not (32 <= char_byte <= 126):
            return
            
        try:
            char = chr(char_byte)
        except:
            return
            
        ident = icmp.id
        seq = icmp.seq
        
        self.id_counts[ident] += 1
        self.char_packets.append((ident, seq, char))
        
        if self.packet_count <= 10:
            print(f"[DEBUG] Packet {self.packet_count}: id=0x{ident:04x}, seq={seq}, char='{char}'")
        
        if self.sender_id is not None and ident == self.sender_id:
            if seq not in self.captured:
                self.captured[seq] = char
                print(f"[+] Seq {seq:3d} -> '{char}' (total: {len(self.captured)})")

def capture_packets(timeout=60):
    print(f"{CYAN}[*] Starting packet capture with Scapy…{RESET}")
    print(f"[*] Listening for ICMP Echo Requests (timeout={timeout}s)")
    
    capture = ICMPCapture()
    
    try:
        sniff(
            filter="icmp and icmp[icmptype]=8",
            prn=capture.packet_handler,
            timeout=timeout,
            store=False
        )
        
        if capture.char_packets:
            id_counter = Counter()
            for ident, seq, char in capture.char_packets:
                id_counter[ident] += 1
            
            print(f"\n[*] Sender IDs detected: {len(id_counter)}")
            for ident, count in id_counter.most_common(5):
                print(f"    ID 0x{ident:04x}: {count} packets")
            
            if id_counter:
                capture.sender_id = id_counter.most_common(1)[0][0]
                print(f"\n[+] Selected sender ID: 0x{capture.sender_id:04x} ({id_counter[capture.sender_id]} packets)")
                
                for ident, seq, char in capture.char_packets:
                    if ident == capture.sender_id and seq not in capture.captured:
                        capture.captured[seq] = char
                        print(f"    Seq {seq:3d} -> '{char}'")
        
    except KeyboardInterrupt:
        print(f"\n[*] Capture stopped by user.")
    
    return capture.captured

def display_results(ciphertext, results):
    W = 80
    best_shift = find_best_shift(results)
    
    print(f"\n{'═' * W}")
    print(f"  Reconstructed text : {BOLD}{ciphertext}{RESET}")
    print(f"  Length              : {len(ciphertext)} characters")
    print(f"{'═' * W}")

    print(f"\n  {BOLD}ALL 26 Caesar shifts (ordered by shift 0-25):{RESET}")
    print(f"  {'─' * (W - 4)}")
    print(f"  {'Shift':>5}   {'Score':>8}   Plaintext")
    print(f"  {'─' * (W - 4)}")

    # Mostrar TODOS los shifts en orden
    for shift, plaintext, score in results:
        line = f"  {shift:>5}   {score:>8.4f}   {plaintext}"
        if shift == best_shift:
            print(f"{GREEN}{BOLD}{line}   ◄  BEST MATCH{RESET}")
        else:
            print(f"{DIM}{line}{RESET}")

    print(f"  {'─' * (W - 4)}")
    
    best_shift, best_plain, best_score = results[best_shift]
    print(f"\n  {BOLD}Best match:{RESET}")
    print(f"  {GREEN}{BOLD}  Shift   : {best_shift}{RESET}")
    print(f"  {GREEN}{BOLD}  Message : {best_plain}{RESET}")
    print(f"  {GREEN}{BOLD}  Score   : {best_score:.4f}{RESET}")
    
    print(f"\n  {DIM}Score = frequency-analysis + dictionary-bonus + structure-bonus{RESET}")
    print(f"  {DIM}Dictionary: {len(SPANISH_WORDS)} common Spanish words loaded{RESET}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='ICMP Caesar-cipher reader',
        epilog='Examples:\n'
               '  sudo python3 readv2.py --timeout 20\n'
               '  sudo python3 readv2.py 20\n'
               '  sudo python3 readv2.py --text "LARYCXPAJORJ H BNPDARMJM NW ANMNB"\n'
               '  sudo python3 readv2.py',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--text', help='Analyse text directly instead of capturing')
    parser.add_argument('--timeout', type=int, default=60, help='Capture timeout in seconds (default: 60)')
    parser.add_argument('--id', type=lambda x: int(x, 0), help='Specific sender ID to capture')
    parser.add_argument('pos_timeout', nargs='?', type=int, help='Positional timeout argument (legacy support: readv2.py 20)')
    
    args = parser.parse_args()
    
    # Si se usó el argumento posicional, usarlo como timeout
    if args.pos_timeout is not None:
        args.timeout = args.pos_timeout
    
    print(f"{CYAN}{BOLD}")
    print("  ┌──────────────────────────────────────────────────┐")
    print("  │  ICMP Caesar-cipher reader  –  Enhanced          │")
    print("  │  With Spanish dictionary for better accuracy    │")
    print("  │  Shows ALL 26 Caesar shifts (0-25)              │")
    print("  └──────────────────────────────────────────────────┘")
    print(f"{RESET}")

    if args.text:
        ciphertext = args.text
        print(f"[*] Analysing provided text: '{ciphertext}'\n")
    else:
        print(f"[*] Starting capture (timeout={args.timeout}s)")
        print(f"[*] Press Ctrl+C to stop early\n")
        packets = capture_packets(args.timeout)
        
        if not packets:
            print(f"{RED}[!] No packets captured.{RESET}")
            print(f"\n{YELLOW}Troubleshooting:{RESET}")
            print(f"  1. Make sure pingv4.py is running with sudo")
            print(f"  2. Check network: ping -c 1 8.8.8.8")
            print(f"  3. Try: sudo python3 readv2.py --timeout 30")
            sys.exit(1)
            
        ciphertext = ''.join(packets[s] for s in sorted(packets))
        print(f"\n[+] Reconstructed: '{ciphertext}' ({len(ciphertext)} chars)")

    if not any(c.isalpha() for c in ciphertext):
        print(f"{RED}[!] No alphabetic characters found.{RESET}")
        sys.exit(1)

    results = all_shifts(ciphertext)
    display_results(ciphertext, results)

if __name__ == "__main__":
    main()