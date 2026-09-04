cat > README.md << 'EOF'
# Laboratorio 1 - Seguridad en Redes
## ICMP Stealth & Caesar Cipher

### Integrantes
- Pablo Muñoz R.

### Descripción
Este proyecto implementa un sistema de filtrado de información a través de tráfico ICMP (ping) que simula el comportamiento del comando `ping` para pasar desapercibido ante sistemas de Deep Packet Inspection (DPI).

### Scripts

#### 1. `cesar.py` - Cifrado César
Cifra texto utilizando el algoritmo de César.

**Uso:**
```bash
sudo python3 cesar.py "texto a cifrar" corrimiento
