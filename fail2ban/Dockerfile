# fail2ban/Dockerfile
FROM debian:stable-slim

RUN apt-get update && apt-get install -y fail2ban iproute2 iptables && rm -rf /var/lib/apt/lists/*

COPY jail.local /etc/fail2ban/
COPY suricata.conf /etc/fail2ban/filter.d/

RUN mkdir -p /var/log/fail2ban
VOLUME /var/log/fail2ban

# Fail2banサーバーを起動し、そのログを標準出力にフォアグラウンドで流し続ける
# これにより、コンテナは終了せず、docker logs で Fail2banの動作状況が見れる
# 起動前にソケットファイルをクリーンアップし、ログファイルを作成
# fail2ban-serverを直接フォアグラウンドで起動することでより安定した動作を実現
CMD ["/bin/bash", "-c", "rm -f /var/run/fail2ban/fail2ban.sock && mkdir -p /var/run/fail2ban && touch /var/log/fail2ban/fail2ban.log && exec fail2ban-server -f"]