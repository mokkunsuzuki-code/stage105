from __future__ import annotations

import json
import struct
import time
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================
# QS-TLS Record Utilities (Stage105)
#  - seq 番号付きレコード
#  - AES-GCM で暗号化
#  - 再送制御マネージャ
# ============================================

def build_record(seq: int, rtype: str, key: bytes, payload: Dict) -> bytes:
    """
    QS-TLS Record を作成して AES-GCM で暗号化する。

    header = {
        "seq": seq,
        "type": rtype,
        "payload": payload,
    }
    """
    header = {
        "seq": seq,
        "type": rtype,
        "payload": payload,
    }
    plaintext = json.dumps(header).encode("utf-8")

    aes = AESGCM(key)
    # seq を 64bit にパックし、12バイトの nonce に拡張（先頭ゼロ埋め）
    nonce = struct.pack("!Q", seq).rjust(12, b"\x00")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return ciphertext


def parse_record(seq: int, key: bytes, ciphertext: bytes) -> Dict:
    """
    受信したレコードを AES-GCM で復号し、dict に戻す。
    復号に使う nonce は送信側と同じく seq から生成する。
    """
    aes = AESGCM(key)
    nonce = struct.pack("!Q", seq).rjust(12, b"\x00")
    plaintext = aes.decrypt(nonce, ciphertext, None)
    header = json.loads(plaintext.decode("utf-8"))
    return header


class RetransmissionManager:
    """
    シンプルな再送制御クラス（Stage105用）

    - 送信したレコードを waiting に登録
    - 一定時間 ACK が来なければ再送対象として返す
    - ACK を受けたら waiting から削除
    """

    def __init__(self, timeout_sec: float = 2.0):
        self.waiting: Dict[int, Dict] = {}  # seq → {"cipher":..., "timestamp":...}
        self.timeout_sec = timeout_sec

    def register(self, seq: int, cipher: bytes) -> None:
        self.waiting[seq] = {
            "cipher": cipher,
            "timestamp": time.time(),
        }

    def ack(self, seq: int) -> None:
        if seq in self.waiting:
            del self.waiting[seq]

    def get_retransmits(self) -> List[Tuple[int, bytes]]:
        """
        timeout_sec 経過しても ACK が来ていないものを再送対象として返す。
        """
        now = time.time()
        resend: List[Tuple[int, bytes]] = []
        for seq, data in list(self.waiting.items()):
            if now - data["timestamp"] > self.timeout_sec:
                resend.append((seq, data["cipher"]))
                # タイムスタンプを更新して、連続再送しすぎないようにする
                data["timestamp"] = now
        return resend
