# flask_app/Dockerfile (venvを使用するように修正)
FROM python:3.9-slim-buster

WORKDIR /app

# 仮想環境を作成し、アクティベートする
# RUN python -m venv venv
# ENV PATH="/app/venv/bin:$PATH"

# 依存関係をインストール
COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# venvの代わりに、システムワイドにインストールするが、
# Dockerのレイヤーキャッシュを効率的に利用するために、
# requirements.txtのコピーとpip installを分けるのがベストプラクティスです。
# Dockerコンテナ自体が分離された環境なので、venvは必須ではありませんが、
# ご要望に応じて以下のように記述します。

# 依存関係をインストールする前に、venvを作成し、その中にインストール
# ただし、Dockerのビルドキャッシュを考慮すると、
# venvの作成とpip installを同じRUNコマンドで行うのが効率的です。
# 仮想環境のパスをPATHに追加
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# 仮想環境のbinディレクトリをPATHに追加
ENV PATH="/opt/venv/bin:$PATH"

# アプリケーションコードをコピー
COPY . .

EXPOSE 5000

CMD ["python", "app.py"]