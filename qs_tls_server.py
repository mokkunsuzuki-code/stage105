# qs_tls_server.py
#
# QS-TLS Stage106 サーバー側
# - QKD(final_key.bin) + X25519(ECDH) + HKDF で AES-256-GCM鍵を生成
# - 暗号化チャット
# - Heartbeat(ハートビート) に対して ACK を返す

import socket
import threading
import time
import json

from crypto_utils import load_qkd_key, derive_hybrid_aes_key, derive_shared_secret
from qs_tls_common import (
    send_record,
    recv_record,
    MSG_TYPE_CHAT,
    MSG_TYPE_HEARTBEAT,
    MSG_TYPE_HEARTBEAT_ACK,
    MSG_TYPE_QUIT,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


HOST = "127.0.0.1"
PORT = 50506


def perform_handshake_server(conn) -> bytes:
    """
    サーバー側ハンドシェイク:
    - X25519 鍵ペア生成
    - 公開鍵をクライアントへ送信
    - クライアントの公開鍵を受信
    - QKD鍵 + ECDH秘密 から AES鍵を導出
    """
    print("[Server] Handshake: start")

    # 1) サーバー X25519 鍵ペア生成
    server_priv = x25519.X25519PrivateKey.generate()
    server_pub_bytes = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 2) サーバー公開鍵をクライアントへ送信
    conn.sendall(server_pub_bytes)
    print("[Server] Sent server X25519 public key")

    # 3) クライアント公開鍵を受信
    client_pub_bytes = _recv_exact(conn, 32)
    if not client_pub_bytes:
        raise ConnectionError("failed to receive client public key")
    print("[Server] Received client X25519 public key")

    # 4) ECDH共有秘密を計算
    shared_secret = derive_shared_secret(server_priv, client_pub_bytes)

    # 5) QKD鍵を読み込み
    qkd_key = load_qkd_key()

    # 6) ハイブリッド鍵から AES-256 鍵を導出
    aes_key = derive_hybrid_aes_key(qkd_key, shared_secret)
    print("[Server] Handshake: AES key derived")

    return aes_key


def _recv_exact(conn, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def handle_client(conn, addr):
    try:
        aes_key = perform_handshake_server(conn)
    except Exception as e:
        print(f"[Server] Handshake failed with {addr}: {e}")
        conn.close()
        return

    print(f"[Server] Handshake complete with {addr}. Encrypted session started.")

    while True:
        try:
            msg = recv_record(conn, aes_key)
        except ConnectionError:
            print(f"[Server] Connection closed from {addr}")
            break
        except Exception as e:
            print(f"[Server] Error while receiving from {addr}: {e}")
            break

        mtype = msg.get("type")
        payload = msg.get("payload", {})

        if mtype == MSG_TYPE_QUIT:
            print(f"[Server] Client {addr} requested quit.")
            break

        elif mtype == MSG_TYPE_HEARTBEAT:
            # ---- Stage106: Heartbeat を受信したら ACK で応答 ----
            orig_ts = payload.get("timestamp")
            now = time.time()
            print(f"[Server] Heartbeat received from {addr}. client_ts={orig_ts}, server_ts={now}")

            ack_msg = {
                "type": MSG_TYPE_HEARTBEAT_ACK,
                "payload": {
                    "orig_timestamp": orig_ts,
                    "server_timestamp": now,
                },
            }
            send_record(conn, aes_key, ack_msg)
            print(f"[Server] Heartbeat ACK sent to {addr}.")

        elif mtype == MSG_TYPE_CHAT:
            text = payload.get("text", "")
            print(f"[Server] Chat from {addr}: {text}")

            # 必要ならエコー返信
            # reply = {
            #     "type": MSG_TYPE_CHAT,
            #     "payload": {"text": f"Echo: {text}"},
            # }
            # send_record(conn, aes_key, reply)

        else:
            print(f"[Server] Unknown message type from {addr}: {mtype}")

    conn.close()
    print(f"[Server] Connection closed: {addr}")


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[Server] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[Server] New connection from {addr}")
            th = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            th.start()


if __name__ == "__main__":
    run_server()
