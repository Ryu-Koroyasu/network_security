# flask_app/app.py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello from Flask Backend!'

@app.route('/health')
def health_check():
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) # 0.0.0.0でリッスンし、どのIPからもアクセス可能にする