import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ssl-info', methods=['GET'])
def ssl_info():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400

    try:
        response = requests.get(f'https://{domain}', timeout=5)
        ssl_info = response.raw.connection.sock.getpeercert()
        return jsonify({
            'domain': domain,
            'ssl_info': ssl_info,
            'status': 'valid' if response.status_code == 200 else 'invalid'
        })
    except requests.exceptions.SSLError as e:
        return jsonify({'domain': domain, 'error': 'SSL error', 'details': str(e)}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'domain': domain, 'error': 'Request error', 'details': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)