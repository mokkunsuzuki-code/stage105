# qs_tls_common.py
#
# QS-TLS Stage106 共通ユーティリティ
# - AES-256-GCM での暗号化/復号
# - 長さプレフィックス付きのレコード送受信
# - メッセージ種別: chat / heartbeat / heartbeat_ack / quit

import json
import os
import struct
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ----- メッセージタイプ定義 -----
MSG_TYPE_CHAT = "chat"
MSG_TYPE_HEARTBEAT = "heartbeat"
MSG_TYPE_HEARTBEAT_ACK = "heartbeat_ack"
MSG_TYPE_QUIT = "quit"


def encrypt_message(key: bytes, message: Dict[str, Any]) -> bytes:
    """
    message(dict) を JSON エンコードして AES-GCM で暗号化。
    返り値: nonce(12byte) + ciphertext
    """
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(message).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_message(key: bytes, data: bytes) -> Dict[str, Any]:
    """
    nonce(12) + ciphertext 形式のデータを復号して dict を返す。
    """
    if len(data) < 12:
        raise ValueError("data too short")

    nonce = data[:12]
    ciphertext = data[12:]
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8", errors="replace"))


def send_record(sock, key: bytes, message: Dict[str, Any]) -> None:
    """
    長さプレフィックス付きレコードを送信。
    [4byte length][nonce+ciphertext]
    """
    enc = encrypt_message(key, message)
    header = struct.pack("!I", len(enc))
    sock.sendall(header + enc)


def recv_record(sock, key: bytes) -> Dict[str, Any]:
    """
    1レコード分を受信して復号して dict を返す。
    """
    # まず長さ(4byte)を読む
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionError("socket closed while reading length")

    (length,) = struct.unpack("!I", header)
    if length <= 0:
        raise ValueError("invalid record length")

    enc = _recv_exact(sock, length)
    if not enc:
        raise ConnectionError("socket closed while reading payload")

    return decrypt_message(key, enc)


def _recv_exact(sock, size: int) -> bytes:
    """
    指定バイト数を受信（それ以下なら None）。
    """
    chunks = []
    total = 0
    while total < size:
        chunk = sock.recv(size - total)
        if not chunk:
            return b""
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)
