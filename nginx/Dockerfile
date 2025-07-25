# nginx/Dockerfile_nginx
FROM nginx

# デフォルトのnginx設定ファイルを削除し、カスタム設定をコピー
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# SSL証明書をコピー
COPY ssl/ /etc/nginx/ssl/

# ログディレクトリの作成（実際のファイルとして出力）
RUN rm -f /var/log/nginx/access.log /var/log/nginx/error.log && \
    mkdir -p /var/log/nginx && \
    touch /var/log/nginx/access.log && \
    touch /var/log/nginx/error.log && \
    chmod 644 /var/log/nginx/access.log /var/log/nginx/error.log

# logsを外部ボリュームにマウント
VOLUME /var/log/nginx