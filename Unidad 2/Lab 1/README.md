# Laboratorio de criptografía cliente-servidor

Equipo: Marcelo Acuña · Abner Arboleda · Andrés Cedeño · Zaith Manangón
Ingeniería de Seguridad del Software · NRC 36893 · Docente: Ing. Milton Arguello

Demostración, en dos máquinas virtuales Ubuntu, de SHA-256, AES-256-GCM, RSA-3072 (PSS y OAEP), X25519/ECDH, Argon2id y un servicio HTTPS con TLS 1.3 analizado con Wireshark.

## Arquitectura

```
CLIENTE cli-cripto 10.10.10.20  ---- red interna cripto-lan ----  SERVIDOR srv-cripto 10.10.10.10
  curl / Wireshark / crypto_lab.py                                  server_https.py :8443
  server.crt (copia confiable)                                      server.crt + server.key (600)
```

Cada VM tiene el adaptador 1 en NAT (solo para instalar paquetes) y el adaptador 2 en la red interna `cripto-lan`. El NAT se desactiva antes de las actividades F y G.

## Contenido

| Archivo | Descripción |
|---|---|
| `crypto_lab.py` | Utilidades de las actividades A–E (ver `python crypto_lab.py --help`) |
| `server_https.py` | Servidor HTTPS didáctico (Anexo A de la guía), solo en el servidor |
| `docs/` | Documento de diseño, diagramas e informe |
| `evidencias/` | Capturas E00–E09 y la captura `E09_captura_tls.pcapng` |

## Preparación (en cada VM, con NAT activo)

```bash
sudo apt update
sudo apt install -y openssl python3 python3-venv python3-pip curl wireshark tcpdump
mkdir -p ~/lab-crypto && cd ~/lab-crypto
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography argon2-cffi
```

IP estática en `/etc/netplan/60-cripto-lan.yaml` (interfaz `enp0s8`): `10.10.10.10/24` en el servidor y `10.10.10.20/24` en el cliente, sin gateway.

## Uso

| Comando | Actividad |
|---|---|
| `python crypto_lab.py hash FILE` | A. SHA-256 |
| `python crypto_lab.py encrypt FILE` / `decrypt FILE.aesgcm [--key K]` | B. AES-256-GCM (clave en `aes.key`) |
| `python crypto_lab.py rsa-keys` / `sign FILE` / `verify FILE FILE.sig` | C. RSA-PSS |
| `python crypto_lab.py rsa-wrap "MSG"` / `rsa-unlock rsa_message.bin` | C. RSA-OAEP |
| `python crypto_lab.py ecdh-demo` | D. X25519 + HKDF |
| `python crypto_lab.py password-hash` / `password-check "$(cat password.hash)"` | E. Argon2id |

Servicio HTTPS (actividad F):

```bash
# [SERVIDOR]
openssl req -x509 -newkey rsa:3072 -sha256 -days 7 -nodes \
  -keyout server.key -out server.crt -subj "/CN=lab.local" \
  -addext "subjectAltName=DNS:lab.local,IP:10.10.10.10"
chmod 600 server.key
python server_https.py

# [CLIENTE] (después de copiar solo server.crt con scp)
curl --cacert server.crt https://10.10.10.10:8443/
curl --cacert server.crt -X POST https://10.10.10.10:8443/ \
  -H 'Content-Type: text/plain' --data 'matricula=ESTUDIANTE-DE-PRUEBA'
```

## Seguridad

- Solo datos ficticios y contraseñas de laboratorio.
- No se versionan claves privadas, certificados, `aes.key`, `password.hash` ni archivos cifrados (ver `.gitignore`).
- No se usa `curl -k`: el certificado autofirmado se valida con `--cacert`.
- Al terminar, las claves se eliminan con `shred -u`.
