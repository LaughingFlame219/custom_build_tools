NetKit 現場ツール v1.1.0
====================================

■ PCで使う
  index.html をダブルクリックしてブラウザで開くだけ。ネット接続は不要です。

■ スマホで使う（オフラインでホーム画面から起動）
  1. このフォルダの中身をすべて、HTTPS で見られる場所に置く
     （社内Webサーバ、NAS のWeb機能、GitHub Pages など）
  2. スマホでそのURLを一度開く → 自動でオフライン用にキャッシュされます
  3. iPhone: Safari の共有ボタン →「ホーム画面に追加」
     Android: Chrome のメニュー →「アプリをインストール」
  4. 以後は圏外・機内モードでもアイコンから起動できます

■ MACベンダーを全件にしたいとき
  ネットにつながる場所で以下のいずれかをダウンロードし、
  アプリの「オフライン」タブで取り込んでください（ブラウザ内に保存されます）。
    https://standards-oui.ieee.org/oui/oui.csv
    https://www.wireshark.org/download/automated/data/manuf

■ ファイル構成
  index.html            アプリ本体（これ1つでも動作）
  sw.js                 オフラインキャッシュ用 Service Worker
  manifest.webmanifest  ホーム画面追加用の設定
  icon-*.png            アイコン
