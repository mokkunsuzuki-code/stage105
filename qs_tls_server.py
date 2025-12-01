from __future__ import annotations

import socket
import threading
from typing import Tuple

from crypto_utils import load_qkd_key, derive_hybrid_key
from qs_tls_common import build_record, parse_record, RetransmissionManager


HOST = "127.0.0.1"
PORT = 50400


def client_handler(conn: socket.socket, addr: Tuple[str, int], aes_key: bytes) -> None:
    """
    クライアント1台分のハンドラ。
    Stage105 では以下を行う：
      - seq 番号付きのメッセージ受信
      - ACK の送信
      - 再送要求への対応（サーバー側からの送信は今回は最小限）
    """
    print(f"[Server] ハンドシェイク完了。クライアント {addr} と通信開始")

    rtx = RetransmissionManager()
    seq_send = 1      # サーバー → クライアント
    seq_recv = 1      # クライアント → サーバー

    while True:
        # 必要な再送があれば送る（今回はサーバーから送るケースは少ないが形だけ用意）
        for rseq, rcipher in rtx.get_retransmits():
            try:
                conn.sendall(rcipher)
                print(f"[Server][RTX] seq={rseq} を再送")
            except OSError:
                print("[Server] 再送時に接続エラーが発生しました。終了します。")
                conn.close()
                return

        try:
            data = conn.recv(4096)
        except ConnectionResetError:
            print("[Server] クライアントが切断しました（ConnectionResetError）。")
            break

        if not data:
            # 空読みは無視して継続
            continue

        # 受信データを復号
        try:
            rec = parse_record(seq_recv, aes_key, data)
        except Exception as e:
            print(f"[Server] 復号エラー: {e}")
            break

        seq_recv += 1
        rtype = rec.get("type")
        payload = rec.get("payload", {})

        if rtype == "ACK":
            # サーバー側から送信したメッセージに対するACK（今回はほぼ使わない）
            ack_seq = payload.get("ack")
            rtx.ack(ack_seq)
            print(f"[Server] ACK 受信: ack={ack_seq}")
            continue

        if rtype == "MSG":
            text = payload.get("text", "")
            print(f"[Server] Client → Server: {text}")

            # 受信したメッセージに対する ACK を返す
            ack_cipher = build_record(
                seq_send,
                "ACK",
                aes_key,
                {"ack": rec.get("seq")}  # 受信したレコードの seq をそのまま返す
            )
            try:
                conn.sendall(ack_cipher)
            except OSError:
                print("[Server] ACK 送信時に接続エラー。終了します。")
                break
            seq_send += 1

        else:
            print(f"[Server] 未知のレコードタイプを受信: {rtype}")

    conn.close()
    print(f"[Server] クライアント {addr} との接続を終了しました。")


def run_server() -> None:
    """
    Stage105 サーバー起動関数。
    - QKD鍵を読み込み
    - ダミー共有秘密（今後 X25519 に置き換え可能）
    - ハイブリッド鍵を生成
    - クライアント接続ごとにスレッドを立てて client_handler を実行
    """
    # QKD鍵読み込み
    qkd_key = load_qkd_key()
    # まだ ECDH を入れていないので、shared_secret はダミー
    dummy_shared_secret = b"A" * 32
    aes_key = derive_hybrid_key(qkd_key, dummy_shared_secret)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[Server] Listening on {HOST}:{PORT} ...")

    try:
        while True:
            conn, addr = s.accept()
            print(f"[Server] 接続受理: {addr}")
            th = threading.Thread(target=client_handler, args=(conn, addr, aes_key), daemon=True)
            th.start()
    finally:
        s.close()
        print("[Server] サーバーソケットを閉じました。")


if __name__ == "__main__":
    run_server()
