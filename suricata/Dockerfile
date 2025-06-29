# suricata/Dockerfile
FROM jasonish/suricata:latest

# Suricata設定ファイルをコピー
COPY suricata.yaml /etc/suricata/suricata.yaml

# カスタムルールをコピー (Docker Composeでボリュームマウントするので、実際は不要だが念のため)
# COPY rules/ /etc/suricata/rules/

# 外部からルールをダウンロードする場合はここに追加

# Nginxログ監視用 (Suricataが直接Nginxのアクセスログを監視する場合)
# この構成ではFail2banがログを処理するので不要
# しかし、SuricataがNginxコンテナのネットワークを監視するために、
# Nginxコンテナと同じネットワークに属し、トラフィックを傍受する必要がある。
# 今回の構成では、NginxのトラフィックをSuricataが直接見るのではなく、
# NginxのアクセスログをFail2banが監視し、そのログに基づいてSuricataのイベントをトリガーし、
# Fail2banがブロックする方式を想定している。
# もしSuricataをインラインIPSとして構成するなら、ネットワーク設定と権限を大幅に変更する必要がある。

# ログディレクトリを作成 (eve.jsonの出力先)
RUN mkdir -p /var/log/suricata
VOLUME /var/log/suricata