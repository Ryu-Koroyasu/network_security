# nginx/Dockerfile_nginx
FROM nginx

# デフォルトのnginx設定ファイルを削除し、カスタム設定をコピー
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# ログディレクトリの作成（アクセスログとエラーログの出力先）
RUN mkdir -p /var/log/nginx
# Nginxコンテナのログファイルを標準出力に転送 (Dockerのベストプラクティス)
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log
VOLUME /var/log/nginx # logsを外部ボリュームにマウント