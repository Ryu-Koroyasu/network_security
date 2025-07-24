# flask_app/app.py
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello from Flask Backend!'

@app.route('/health')
def health_check():
    return 'OK', 200

@app.route('/test')
def test_endpoint():
    """テスト用エンドポイント - Suricataルールでキャッチされる"""
    file_param = request.args.get('file', '')
    if file_param:
        return f'Test endpoint accessed with file parameter: {file_param}', 200
    return 'Test endpoint accessed', 200

@app.route('/admin')
def admin_endpoint():
    """管理者エンドポイント - ブルートフォース攻撃の対象"""
    return 'Admin access denied', 403

@app.route('/api/data')
def api_data():
    """API エンドポイント"""
    return jsonify({
        'message': 'API response',
        'timestamp': time.time(),
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    })

@app.route('/login', methods=['POST'])
def login():
    """ログインエンドポイント（攻撃対象として）"""
    return 'Login failed', 401

@app.route('/search')
def search():
    """検索エンドポイント（SQLインジェクション攻撃の対象）"""
    query = request.args.get('q', '')
    return f'Search results for: {query}', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) # nginxの設定に合わせてポート5000を使用