# suricata/Dockerfile
FROM jasonish/suricata:latest

# Suricata設定ファイルをコピー
# これにより、/etc/suricata/suricata.yaml はコンテナイメージの一部となり、
# 実行時のパーミッション問題を回避します。
COPY suricata.yaml /etc/suricata/suricata.yaml

# カスタムルールをコピー
# 同様に、ルールもイメージに含めることで実行時の問題を回避
COPY rules/ /etc/suricata/rules/ 
# rulesディレクトリ全体をコピー

# ログディレクトリを作成 (eve.jsonの出力先)
RUN mkdir -p /var/log/suricata
VOLUME /var/log/suricata # ログは永続化のためボリュームマウントを維持

# IPSモードで動作（AF_PACKET copy-mode=ips）
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0", "--runmode", "autofp", "-v"]