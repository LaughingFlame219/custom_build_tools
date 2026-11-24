# Policy Tester (トラフィックジェネレーター)

シナリオCSV と 仮想ルーター設定(TOML) を読み込み、ファイアウォール越しに実トラフィックを流して
**Pass / Drop / Block / Error** を判定します。Python 3.8+ 標準ライブラリのみ (3.10以下は内蔵の簡易TOMLパーサを使用) (Windows + Npcap)。

## 使い方
```
python trafficgen.py                  # ブラウザUIが開く (127.0.0.1:8080)
python trafficgen.py devices          # Npcapで見えるNIC名 (= TOMLの os_if に書く名前)
python trafficgen.py run scenario.csv --vrouter vr.toml -o result.csv
python trafficgen.py run ... --sim    # 疑似FWで自己診断 (NIC不要)
python run_tests.py                   # 自動テスト
```
入力は `scenario_gen.py` が出力する CSV / TOML そのままです。

## 前提 (Windows実機)
- Npcap を「WinPcap API-compatible Mode」付きでインストール
- テスター用NICは **OS側にIPを割り当てない** (仮想ルーターのIPはこのツールが持ちます)
- VLANを使う場合、NICドライバの「Priority & VLAN」(VLANタグ除去) を **無効** に
  (有効だと受信時にタグが剥がされ、VLAN側の応答が見えません)
- 管理者権限は不要 (Npcapのインストール設定による)

## 画面 (NEEDLEWORK風)
- シナリオCSVをそのままグリッド表示し、セルをダブルクリック/Enter/タイプで直接編集 (Excelからの貼り付けも可、空行に入力すると行追加)
- 上部カウンタ All / Pass / Drop / Block / Error / Others (クリックで絞り込み)、列ヘッダ▼で列フィルタ
- pass=緑塗り、error=行を赤。エラーの詳細(ARP応答なし等)は左サイドバーに表示
- 「仮想ルーター設定(TOML)を読み込む」「シナリオを自動生成する」(FortiGate/Paloコンフィグ→CSV+TOML)
- 「エビデンス保存」= 結果CSV + 仮想ルーター設定(TOML) + 詳細CSV + summary(+pcap) のZIP
- ☰ メニューから「インターフェース設定」「仮想ルーター設定」を画面で編集 (IF・VLANの追加/削除、VRの追加/編集/削除、ルート編集、L2モード、設定ファイルの読込/保存、設定を適用、テスト構成確認)。適用時に重複・/31・所属重複などを検証
- ☰ →「実行オプション」で同時実行数・timeout・FQDN→IP・pcap・疑似FW実行を設定

## 判定
| 結果 | 意味 |
|---|---|
| Pass | 受信側の疑似サーバーまで届き期待どおりの応答 (SYN/ACK, echo reply, HTTP 200 等) |
| Drop | 応答なし (タイムアウト) |
| Block | RST / ICMP unreachable / ブロックページ / DNS書換え(sinkhole) / EICARが届かない |
| Error | ARP未解決(FWが見えない)・経路なし・FQDN未解決など、テスター側の問題 |

`judge` 列は expect との一致 (OK/NG)。`--lenient` で expect が drop/block のとき両者を同一視。

## 列の意味
`dst-ip`=クライアントが送る宛先 / `dst-nat-ip`,`dst-nat-port`=FWのDNAT後に受信側が待つアドレス
(受信側サーバーはこちらで待ち受けます) / `src-nat-ip`=SNAT後に受信側で観測される送信元 (不一致なら NG) /
`is-receiver-physical`=宛先が実機サーバー (疑似サーバーを立てず、緩い判定) /
`url/domain`=HTTP Host・TLS SNI・DNS問い合わせ名 / `anti-virus`=EICARを流す /
`timeout`秒 / `try`=不一致時の再試行回数。

## コンフィグからの自動生成 (FortiGate / Palo Alto)
「シナリオを自動生成する」(または `python scenario_gen.py <config>`) でシナリオCSVと仮想ルーター設定(TOML)を作ります。

### Palo Alto
- 形式: XML (running-config / Panorama) と set形式。vsysが複数ある場合は FortiGate の vdom と同様に vsys ごとに出力
- 仮想ルーター(TOML): ポリシーで使うゾーンのレイヤー3インターフェースごとに テスター側IF+仮想ルーターを作成
  (サブインターフェースはVLAN、仮想ルーター名=ゾーン名。DHCP/IP未設定のIFは作れないので警告。`tester_ip` で上書き可)
- **NAT対応**: NATルールを上から順に照合し、最初にマッチした1件で期待値を決めます
  - 送信元NAT: dynamic-ip-and-port (interface-address / translated-address)、dynamic-ip、static-ip (1:1。bi-directionalは逆方向も) → `src-nat-ip`
  - 宛先NAT: translated-address / translated-port → `dst-nat-ip` / `dst-nat-port` (`dst-ip` はセキュリティルールの宛先=変換前アドレス)
  - NATなし(no-nat)・無効ルールにも対応。プールは先頭アドレスを期待値に使い、description に注記
  - 制約: 宛先NATルールの `to` ゾーンは変換前宛先のルーティングで決まるため照合に使いません。NAT64・dynamic-ipのfallback・DNS rewrite 等は未対応(警告)
- 外部動的リスト(EDL)・動的アドレスグループ・FQDNは解決できないため警告

### ポリシーが大量のとき
1ポリシーの (送信元×宛先×サービス×ゾーン) の組合せが **組合せ上限 (`--max-combo`、既定100)** を超えると、全ての値を最低1回ずつ使う形に間引きます
(`0` で全組合せ)。ほかに `--max-per-policy` (ポリシーあたり最大件数)。間引いたポリシーは警告に出ます。

## 出力
- `result.csv` : 入力と同じ17列で `result` を埋めたもの
- `result.csv.detail.csv` : + judge / detail / elapsed_ms / observed_src / observed_dst / cert_issuer / ssl_inspected
- `--pcap` : 送受信フレーム (証跡)

## exe 化
`build_exe.bat` (PyInstaller)。

## 制限
- Windows実機のNpcap経由の送受信は、この開発環境では未検証 (疑似FWでの自動テストのみ)
- ping-traceroute 列は未使用 / HTTPSの復号(SSLインスペクション)はissuer差で検出のみ
- IPv4のみ、フラグメント非対応、TCPは順序入替に再送で対応する簡易実装
