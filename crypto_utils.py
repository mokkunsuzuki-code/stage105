# crypto_utils.py
#
# Stage106 ハイブリッド鍵生成ユーティリティ
# QKD鍵(final_key.bin) + X25519(ECDH) を HKDF で混合して
# AES-256-GCM の鍵を生成する

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

FINAL_KEY_PATH = Path("final_key.bin")


def load_qkd_key(path: Path = FINAL_KEY_PATH) -> bytes:
    """QKD 最終鍵を読み込む（32バイトに調整）"""
    data = path.read_bytes()
    if len(data) < 32:
        data = data.ljust(32, b"\x00")
    return data[:32]


def derive_shared_secret(private_key: x25519.X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    """X25519 の共有秘密を導出"""
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return private_key.exchange(peer_pub)


def derive_hybrid_aes_key(qkd_key: bytes, ecdh_secret: bytes, length: int = 32) -> bytes:
    """
    QKD鍵 + ECDH共有秘密 → ハイブリッド鍵 → AES-256鍵を HKDF で導出
    """
    ikm = qkd_key + ecdh_secret  # これがハイブリッド鍵の"材料"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"qs-tls-stage106",
    )
    return hkdf.derive(ikm)
