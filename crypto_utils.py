from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# QKDで生成された最終鍵ファイルのパス
QKD_KEY_PATH = Path("final_key.bin")


# ==============================
# QKD 鍵関連
# ==============================

def load_qkd_key(path: str | Path = QKD_KEY_PATH) -> bytes:
    """
    QKDで生成された final_key.bin を読み込むヘルパー関数。
    32バイト以上あることを簡易チェックする。
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"QKD鍵ファイルが見つかりません: {p}")

    data = p.read_bytes()
    if len(data) < 32:
        raise ValueError(f"QKD鍵が短すぎます ({len(data)} バイト)。32バイト以上が必要です。")

    return data


# ==============================
# ハイブリッド鍵導出 (QKD + ECDH共有秘密)
# ==============================

def derive_hybrid_key(
    qkd_key: bytes,
    shared_secret: bytes,
    *,
    length: int = 32,
    info: bytes = b"qs-tls-1.0 hybrid key",
) -> bytes:
    """
    QKD鍵(qkd_key) と ECDH共有秘密(shared_secret) を HKDF でミックスして、
    AES-256 で利用する 32バイトのハイブリッドセッション鍵を生成する。

    Stage105 では shared_secret としてダミー値 (b"A"*32 など) を使ってもOK。
    将来的に X25519 の実際の共有秘密を入れれば、そのまま拡張できる。
    """
    if not isinstance(qkd_key, (bytes, bytearray)):
        raise TypeError("qkd_key は bytes である必要があります。")
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise TypeError("shared_secret は bytes である必要があります。")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=qkd_key,  # 量子鍵を salt として利用
        info=info,     # プロトコル識別用のコンテキスト
    )
    return hkdf.derive(shared_secret)


# ==============================
# AES-GCM ユーティリティ（必要なら使用）
# ==============================

def encrypt_aes_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """
    AES-GCM で暗号化するシンプルなヘルパー。
    qs_tls_common.py では直接 AESGCM を使っているが、
    他のモジュールから利用したいとき用。
    """
    aes = AESGCM(key)
    return aes.encrypt(nonce, plaintext, aad)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """
    AES-GCM 復号用ヘルパー。
    """
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)
