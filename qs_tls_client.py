from __future__ import annotations

import socket
import threading
from typing import List

from crypto_utils import load_qkd_key, derive_hybrid_key
from qs_tls_common import build_record, parse_record, RetransmissionManager


HOST = "127.0.0.1"
PORT = 50400


def recv_loop(conn: socket.socket, aes_key: bytes, rtx: RetransmissionManager, seq_recv_ref: List[int]) -> None:
    """
    受信専用スレッド。
    - サーバーからの ACK を処理
    - 必要なら将来サーバー→クライアントのMSGも処理可能
    """
    while True:
        try:
            data = conn.recv(4096)
        except ConnectionResetError:
            print("[Client] サーバーが切断しました。")
            break

        if not data:
            continue

        try:
            rec = parse_record(seq_recv_ref[0], aes_key, data)
        except Exception as e:
            print(f"[Client] 復号エラー: {e}")
            break

        seq_recv_ref[0] += 1

        rtype = rec.get("type")
        payload = rec.get("payload", {})

        if rtype == "ACK":
            ack_seq = payload.get("ack")
            rtx.ack(ack_seq)
            print(f"[Client] ACK 受信: ack={ack_seq}")
        elif rtype == "MSG":
            print(f"[Client] Server → Client: {payload.get('text')}")
        else:
            print(f"[Client] 未知のレコードタイプ受信: {rtype}")

    conn.close()
    print("[Client] 受信スレッド終了。")


def run_client() -> None:
    """
    Stage105 クライアント。
    - サーバーに接続
    - QKD鍵 + ダミー共有秘密からハイブリッド鍵を生成
    - ユーザー入力を MSG レコードとして送信
    - ACK が来ない場合は自動で再送
    """
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    print(f"[Client] サーバーに接続しました: {HOST}:{PORT}")

    # ハイブリッド鍵生成
    qkd_key = load_qkd_key()
    dummy_shared_secret = b"A" * 32
    aes_key = derive_hybrid_key(qkd_key, dummy_shared_secret)

    rtx = RetransmissionManager()
    seq_send = 1
    seq_recv_ref = [1]  # 参照渡し用のリスト

    # 受信スレッド起動
    th = threading.Thread(target=recv_loop, args=(conn, aes_key, rtx, seq_recv_ref), daemon=True)
    th.start()

    try:
        while True:
            # 未ACKのものがあれば再送
            for rseq, rcipher in rtx.get_retransmits():
                try:
                    conn.sendall(rcipher)
                    print(f"[Client][RTX] seq={rseq} を再送")
                except OSError:
                    print("[Client] 再送時に接続エラー。終了します。")
                    conn.close()
                    return

            text = input("送信メッセージを入力 (/quit で終了) > ")

            if text.strip() == "/quit":
                print("[Client] 終了します。")
                break

            cipher = build_record(
                seq_send,
                "MSG",
                aes_key,
                {"text": text},
            )
            try:
                conn.sendall(cipher)
            except OSError:
                print("[Client] 送信時に接続エラー。終了します。")
                break

            # 再送管理に登録
            rtx.register(seq_send, cipher)
            seq_send += 1

    finally:
        conn.close()
        print("[Client] 接続を閉じました。")


if __name__ == "__main__":
    run_client()
