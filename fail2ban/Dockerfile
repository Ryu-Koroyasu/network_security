# fail2ban/Dockerfile
FROM debian:stable-slim

RUN apt-get update && apt-get install -y \
    fail2ban \
    iproute2 \
    iptables \
    python3 \
    python3-systemd \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY jail.local /etc/fail2ban/
COPY suricata.conf /etc/fail2ban/filter.d/
COPY filter.d/ /etc/fail2ban/filter.d/

RUN mkdir -p /var/log/fail2ban /var/run/fail2ban
VOLUME /var/log/fail2ban

# Fail2ban起動スクリプトをコピー
COPY start-fail2ban.sh /usr/local/bin/start-fail2ban.sh
RUN chmod +x /usr/local/bin/start-fail2ban.sh

# Fail2banサーバーを起動し、そのログを標準出力にフォアグラウンドで流し続ける
# 起動前にソケットファイルをクリーンアップし、ログファイルを作成
CMD ["/usr/local/bin/start-fail2ban.sh"]