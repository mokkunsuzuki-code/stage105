# qs_tls_client.py
#
# QS-TLS Stage106 クライアント側
# - サーバーと X25519 + QKD でハイブリッド鍵交換
# - AES-256-GCM で暗号チャット
# - /ping で Heartbeat を送信し、RTT(往復時間)を計測

import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from crypto_utils import load_qkd_key, derive_hybrid_aes_key, derive_shared_secret
from qs_tls_common import (
    send_record,
    recv_record,
    MSG_TYPE_CHAT,
    MSG_TYPE_HEARTBEAT,
    MSG_TYPE_HEARTBEAT_ACK,
    MSG_TYPE_QUIT,
)


HOST = "127.0.0.1"
PORT = 50506

_last_ping_ts = None  # Heartbeat RTT計測用


def perform_handshake_client(sock) -> bytes:
    """
    クライアント側ハンドシェイク:
    - サーバー公開鍵(X25519)を受信
    - 自分の公開鍵を送信
    - 共有秘密を計算
    - QKD鍵 + ECDH秘密 から AES鍵を導出
    """
    print("[Client] Handshake: start")

    # 1) サーバー公開鍵を受信
    server_pub_bytes = _recv_exact(sock, 32)
    if not server_pub_bytes:
        raise ConnectionError("failed to receive server public key")
    print("[Client] Received server X25519 public key")

    # 2) クライアント側の X25519 鍵ペア生成
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 3) 自分の公開鍵をサーバーへ送信
    sock.sendall(client_pub_bytes)
    print("[Client] Sent client X25519 public key")

    # 4) 共有秘密を計算
    shared_secret = derive_shared_secret(client_priv, server_pub_bytes)

    # 5) QKD鍵を読み込み
    qkd_key = load_qkd_key()

    # 6) ハイブリッド鍵から AES-256 鍵を導出
    aes_key = derive_hybrid_aes_key(qkd_key, shared_secret)
    print("[Client] Handshake: AES key derived")

    return aes_key


def _recv_exact(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def recv_loop(sock, aes_key: bytes):
    """
    サーバーからのメッセージ受信ループ（別スレッド）
    """
    global _last_ping_ts

    while True:
        try:
            msg = recv_record(sock, aes_key)
        except ConnectionError:
            print("[Client] Connection closed by server.")
            break
        except Exception as e:
            print("[Client] Error while receiving:", e)
            break

        mtype = msg.get("type")
        payload = msg.get("payload", {})

        if mtype == MSG_TYPE_CHAT:
            text = payload.get("text", "")
            print(f"\n[Client] Server: {text}")

        elif mtype == MSG_TYPE_HEARTBEAT_ACK:
            orig_ts = payload.get("orig_timestamp")
            server_ts = payload.get("server_timestamp")
            now = time.time()
            if isinstance(orig_ts, (int, float)):
                rtt_ms = (now - orig_ts) * 1000.0
                print(f"\n[Client] Heartbeat ACK 受信 ✅ RTT ≒ {rtt_ms:.1f} ms (server_ts={server_ts})")
            else:
                print("\n[Client] Heartbeat ACK 受信 ✅ (timestampなし)")

        elif mtype == MSG_TYPE_HEARTBEAT:
            # 通常クライアントから送るので基本来ない
            print("\n[Client] Heartbeat を受信（想定外）:", payload)

        elif mtype == MSG_TYPE_QUIT:
            print("\n[Client] Server requested quit.")
            break

        else:
            print("\n[Client] Unknown message type:", mtype)


def run_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[Client] Connected to {HOST}:{PORT}")

        aes_key = perform_handshake_client(sock)
        print("[Client] Handshake complete. Encrypted session started.")
        print("  - 通常メッセージ: そのまま入力して Enter")
        print("  - ハートビート: /ping")
        print("  - 終了: /quit")

        # サーバーからのメッセージを受信するスレッド
        th = threading.Thread(target=recv_loop, args=(sock, aes_key), daemon=True)
        th.start()

        while True:
            user_input = input("送信メッセージ (/ping or /quit) > ").strip()

            if user_input == "/quit":
                msg = {
                    "type": MSG_TYPE_QUIT,
                    "payload": {},
                }
                send_record(sock, aes_key, msg)
                print("[Client] /quit を送信しました。終了します。")
                break

            elif user_input == "/ping":
                # ---- Stage106: Heartbeat 送信 ----
                now = time.time()
                msg = {
                    "type": MSG_TYPE_HEARTBEAT,
                    "payload": {
                        "timestamp": now,
                    },
                }
                send_record(sock, aes_key, msg)
                print("[Client] Heartbeat(/ping) を送信しました。")
                # RTT計測は recv_loop 側で ACK を受けた時に行う
                continue

            else:
                # 通常チャット
                msg = {
                    "type": MSG_TYPE_CHAT,
                    "payload": {"text": user_input},
                }
                send_record(sock, aes_key, msg)


if __name__ == "__main__":
    run_client()
