#!/usr/bin/env python3
"""Utilidades criptográficas didácticas. Solo para laboratorio local.

Usa exclusivamente primitivas estándar de las bibliotecas cryptography y
argon2-cffi; no implementa algoritmos propios.
"""
import argparse
import getpass
import hashlib
import os
import sys

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"AESGCM1"          # cabecera de 7 bytes del archivo cifrado
NONCE_LEN = 12              # 96 bits
PRIVATE_KEY = "rsa_private.pem"
PUBLIC_KEY = "rsa_public.pem"
RSA_MESSAGE = "rsa_message.bin"
PASSWORD_FILE = "password.hash"


def write_secret(path, data):
    """Escribe un archivo legible solo por el dueño (permisos 600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def fail(msg):
    print(f"[ERROR] {msg}")
    sys.exit(1)


def passphrase_bytes(args):
    return args.passphrase.encode() if args.passphrase else None


# --- Actividad A: SHA-256 -------------------------------------------------

def cmd_hash(args):
    h = hashlib.sha256()
    with open(args.file, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    print(f"SHA-256({args.file}) = {h.hexdigest()}")


# --- Actividad B: AES-256-GCM ---------------------------------------------

def cmd_encrypt(args):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_LEN)
    with open(args.file, "rb") as f:
        plaintext = f.read()
    # La cabecera se autentica como dato asociado (AAD)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    out = args.file + ".aesgcm"
    with open(out, "wb") as f:
        f.write(MAGIC + nonce + ciphertext)
    write_secret(args.key, key)
    print("[OK] Algoritmo: AES-256-GCM | clave: 256 bits | nonce: 96 bits | tag: 128 bits")
    print(f"[OK] Archivo cifrado: {out} ({len(MAGIC) + NONCE_LEN + len(ciphertext)} bytes)")
    print(f"[OK] Clave guardada APARTE en {args.key} (permisos 600)")
    print(f"     nonce = {nonce.hex()}")


def cmd_decrypt(args):
    try:
        with open(args.key, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        fail(f"No existe {args.key}")
    with open(args.file, "rb") as f:
        blob = f.read()
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_LEN + 16:
        fail("El archivo no tiene el formato AESGCM1 esperado.")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
    ciphertext = blob[len(MAGIC) + NONCE_LEN:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except (InvalidTag, ValueError):
        fail("Autenticación fallida (InvalidTag): el archivo fue alterado o la clave "
             "es incorrecta. No se entrega texto plano.")
    # acta.txt.aesgcm -> acta.recovered
    base = args.file[:-len(".aesgcm")] if args.file.endswith(".aesgcm") else args.file
    out = os.path.splitext(base)[0] + ".recovered"
    with open(out, "wb") as f:
        f.write(plaintext)
    print(f"[OK] Etiqueta GCM válida. Archivo recuperado: {out}")


# --- Actividad C: RSA-PSS y RSA-OAEP --------------------------------------

def load_private(args):
    try:
        with open(PRIVATE_KEY, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=passphrase_bytes(args))
    except FileNotFoundError:
        fail(f"No existe {PRIVATE_KEY}; ejecute primero: python crypto_lab.py rsa-keys")
    except (TypeError, ValueError):
        fail("No se pudo abrir la clave privada (¿falta o es incorrecta la --passphrase?).")


def load_public():
    try:
        with open(PUBLIC_KEY, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        fail(f"No existe {PUBLIC_KEY}; ejecute primero: python crypto_lab.py rsa-keys")


PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def cmd_rsa_keys(args):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pw = passphrase_bytes(args)
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    write_secret(PRIVATE_KEY, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    with open(PUBLIC_KEY, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print("[OK] Par RSA 3072 bits generado (e=65537)")
    print(f"     Privada: {PRIVATE_KEY} (600, NO compartir) | Pública: {PUBLIC_KEY}")


def cmd_sign(args):
    key = load_private(args)
    with open(args.file, "rb") as f:
        signature = key.sign(f.read(), PSS, hashes.SHA256())
    out = args.file + ".sig"
    with open(out, "wb") as f:
        f.write(signature)
    print(f"[OK] Firma RSA-PSS/SHA-256 ({len(signature)} bytes) -> {out}")


def cmd_verify(args):
    pub = load_public()
    with open(args.file, "rb") as f:
        data = f.read()
    with open(args.signature, "rb") as f:
        signature = f.read()
    try:
        pub.verify(signature, data, PSS, hashes.SHA256())
    except InvalidSignature:
        print(f"[FALLO] FIRMA INVÁLIDA: {args.file} fue modificado o la firma no corresponde")
        sys.exit(1)
    print(f"[OK] FIRMA VÁLIDA: {args.file} no fue modificado y la firmó el dueño de {PRIVATE_KEY}")


def cmd_rsa_wrap(args):
    pub = load_public()
    message = args.message.encode("utf-8")
    limit = pub.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    if len(message) > limit:
        fail(f"El mensaje ({len(message)} bytes) supera el límite OAEP de {limit} bytes. "
             "Use AES-GCM para datos grandes.")
    ciphertext = pub.encrypt(message, OAEP)
    with open(RSA_MESSAGE, "wb") as f:
        f.write(ciphertext)
    print(f"[OK] RSA-OAEP/SHA-256: {len(message)} bytes -> {len(ciphertext)} bytes en {RSA_MESSAGE}")
    print(f"     Límite RSA-{pub.key_size} OAEP-SHA256: {limit} bytes de mensaje")


def cmd_rsa_unlock(args):
    key = load_private(args)
    with open(args.file, "rb") as f:
        ciphertext = f.read()
    try:
        message = key.decrypt(ciphertext, OAEP)
    except ValueError:
        fail("No se pudo descifrar: el mensaje fue alterado o no corresponde a esta clave.")
    print(f"[OK] Mensaje descifrado: {message.decode('utf-8', errors='replace')}")


# --- Actividad D: X25519 / ECDH -------------------------------------------

def derive(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"lab-crypto ecdh-demo").derive(shared)


def raw_public(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def cmd_ecdh_demo(args):
    alice = x25519.X25519PrivateKey.generate()
    bob = x25519.X25519PrivateKey.generate()
    alice_pub, bob_pub = raw_public(alice), raw_public(bob)
    # Cada parte solo recibe la pública de la otra
    secret_alice = alice.exchange(x25519.X25519PublicKey.from_public_bytes(bob_pub))
    secret_bob = bob.exchange(x25519.X25519PublicKey.from_public_bytes(alice_pub))
    print(f"Alice pública (se envía): {alice_pub.hex()}")
    print(f"Bob pública (se envía):   {bob_pub.hex()}")
    print(f"Secreto calculado por Alice: {secret_alice.hex()}")
    print(f"Secreto calculado por Bob  : {secret_bob.hex()}")
    print(f"¿Coinciden? {'SÍ' if secret_alice == secret_bob else 'NO'}")
    print(f"Clave de sesión HKDF-SHA256 (Alice): {derive(secret_alice).hex()}")
    print(f"Clave de sesión HKDF-SHA256 (Bob)  : {derive(secret_bob).hex()}")
    print("Las claves privadas NUNCA se transmitieron.")


# --- Actividad E: Argon2id ------------------------------------------------

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                        hash_len=32, salt_len=16)


def cmd_password_hash(args):
    pw = getpass.getpass("Contraseña de laboratorio: ")
    if pw != getpass.getpass("Repita la contraseña: "):
        fail("Las contraseñas no coinciden.")
    if not pw:
        fail("La contraseña no puede estar vacía.")
    encoded = HASHER.hash(pw)
    write_secret(PASSWORD_FILE, encoded.encode())
    print(f"[OK] Hash Argon2id guardado en {PASSWORD_FILE}")


def cmd_password_check(args):
    pw = getpass.getpass("Contraseña a verificar: ")
    try:
        HASHER.verify(args.encoded.strip(), pw)
    except VerifyMismatchError:
        print("[FALLO] Contraseña INCORRECTA")
        sys.exit(1)
    except InvalidHashError:
        fail("El hash recibido no es un hash Argon2 válido.")
    print("[OK] Contraseña CORRECTA")


def main():
    p = argparse.ArgumentParser(
        description="Laboratorio de criptografía: SHA-256, AES-256-GCM, RSA, X25519 y Argon2id.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("hash", help="SHA-256 de un archivo")
    s.add_argument("file")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("encrypt", help="Cifra con AES-256-GCM (clave en aes.key)")
    s.add_argument("file")
    s.add_argument("--key", default="aes.key")
    s.set_defaults(func=cmd_encrypt)

    s = sub.add_parser("decrypt", help="Descifra un .aesgcm a .recovered")
    s.add_argument("file")
    s.add_argument("--key", default="aes.key")
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("rsa-keys", help="Genera un par RSA-3072")
    s.add_argument("--passphrase")
    s.set_defaults(func=cmd_rsa_keys)

    s = sub.add_parser("sign", help="Firma con RSA-PSS/SHA-256")
    s.add_argument("file")
    s.add_argument("--passphrase")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="Verifica una firma RSA-PSS")
    s.add_argument("file")
    s.add_argument("signature")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("rsa-wrap", help="Cifra un mensaje corto con RSA-OAEP")
    s.add_argument("message")
    s.set_defaults(func=cmd_rsa_wrap)

    s = sub.add_parser("rsa-unlock", help="Descifra un mensaje RSA-OAEP")
    s.add_argument("file")
    s.add_argument("--passphrase")
    s.set_defaults(func=cmd_rsa_unlock)

    s = sub.add_parser("ecdh-demo", help="Acuerdo X25519 entre dos pares efímeros")
    s.set_defaults(func=cmd_ecdh_demo)

    s = sub.add_parser("password-hash", help="Genera un hash Argon2id (entrada oculta)")
    s.set_defaults(func=cmd_password_hash)

    s = sub.add_parser("password-check", help="Verifica una contraseña contra un hash Argon2id")
    s.add_argument("encoded")
    s.set_defaults(func=cmd_password_check)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
