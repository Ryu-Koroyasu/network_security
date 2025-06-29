# fail2ban/Dockerfile
FROM debian:stable-slim

RUN apt-get update && apt-get install -y fail2ban iproute2 iptables && rm -rf /var/lib/apt/lists/*

COPY jail.local /etc/fail2ban/
COPY suricata.conf /etc/fail2ban/filter.d/

# Fail2banのログディレクトリを作成
RUN mkdir -p /var/log/fail2ban
VOLUME /var/log/fail2ban

# コンテナ起動時にFail2banを開始
CMD ["/usr/bin/fail2ban-client", "-D", "start"]