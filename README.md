📘 QS-TLS Stage106 – Encrypted Messaging with Hybrid Quantum-Secure Key Exchange

🄫 2024 Motohiro Suzuki
Licensed under the MIT License
━━━━━━━━━━━━━━━━━━

📌 概要（Overview）

Stage106 は、量子安全通信プロトコル QS-TLS の第6段階です。
ここでは QKD鍵 + X25519 鍵共有 + HKDF で派生した AES-256-GCM セッション鍵を用いて、
完全に暗号化されたリアルタイムメッセージ通信 を実現しています。

🔐 Stage106 の主な特徴

QKD（量子鍵配送）由来の鍵を利用

X25519 ECDH による鍵共有

HKDF で混合鍵から AES-256-GCM 鍵を導出

完全暗号化メッセージチャット（/quit で終了）

**ACK（受信確認）**実装で信頼性を向上

サーバー側は複数クライアントに対応（並列スレッド）

この段階で、QS-TLS は 安全な暗号チャット を実用レベルで実現しています。

🧠 アーキテクチャ（Architecture）
🔑 1. 鍵交換フェーズ
Client → Server : ClientHello
Server → Client : ServerHello
双方の X25519 公開鍵交換
↓
QKD鍵 + ECDH共有鍵 → HKDF → AES-256 セッション鍵

🔒 2. 暗号化メッセージフェーズ
Client/Server:
  AES-256-GCM で暗号化されたメッセージ送信
  → ACK（受信確認）

📴 3. セッション終了
/quit → close_notify → セッション終了


TLS1.3 に近い構造で、
暗号技術としてもポスト量子時代に適した方式になっています。

📂 ディレクトリ構成（Project Structure）
stage106/
│
├── qs_tls_client.py        # クライアント実装（暗号チャット）
├── qs_tls_server.py        # サーバー実装（複数接続対応）
├── qs_tls_common.py        # 共通レコード層 / AES / HKDF
├── pq_sign.py              # SPHINCS+ 署名関連（Stage103〜）
├── manifest_utils.py       # ディレクトリ同期の下地（Stage102〜）
├── crypto_utils.py         # QKD鍵読込 + X25519 + HKDF
│
├── client_keys/            # クライアントごとの鍵（自動生成）
│   └── ...pem
│
└── server_keys/            # サーバー側の署名鍵

▶️ 実行方法（How to Run）
1. サーバー起動
cd stage106
python3 qs_tls_server.py

2. クライアント起動（別ターミナル）
cd stage106
python3 qs_tls_client.py

3. メッセージ送信
こんにちは
テストです
/quit


クライアントとサーバー間の通信は全て
AES-256-GCM により暗号化されています。

🧩 ライセンス（MIT License）
MIT License

Copyright (c) 2024 Motohiro Suzuki

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
