
from flask import Flask, render_template_string, request, send_file, make_response
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import io
import os

app = Flask(__name__)

def generate_rsa_keys():
    """Tạo cặp khóa RSA"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_data(data, private_key):
    """Ký số dữ liệu"""
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature, public_key):
    """Xác minh chữ ký"""
    try:
        key = RSA.import_key(public_key)
        h = SHA256.new(data)
        signature_bytes = base64.b64decode(signature)
        pkcs1_15.new(key).verify(h, signature_bytes)
        return True
    except:
        return False

def encrypt_file_data(data, key):
    """Mã hóa dữ liệu file"""
    key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return iv + ct_bytes

def decrypt_file_data(encrypted_data, key):
    """Giải mã dữ liệu file"""
    key_bytes = key.encode('utf-8')[:32].ljust(32, b'\0')
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

html_template = '''
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ứng Dụng Bảo Mật File & Ký Số</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            max-width: 900px;
            width: 95%;
            margin: 2rem auto;
            padding: 2.5rem;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(15px);
        }

        h1 {
            text-align: center;
            color: #4a4a4a;
            margin-bottom: 2rem;
            font-size: 2.5rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .tabs {
            display: flex;
            justify-content: center;
            margin-bottom: 2.5rem;
            gap: 1.5rem;
        }

        .tab-btn {
            padding: 1rem 3rem;
            border: none;
            background: #f0f0f0;
            border-radius: 50px;
            cursor: pointer;
            font-size: 1.1rem;
            font-weight: 600;
            transition: all 0.3s ease;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .tab-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
        }

        .tab-btn.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .tab-content.active {
            display: block;
        }

        .form-group {
            margin-bottom: 2rem;
        }

        label {
            display: block;
            margin-bottom: 0.8rem;
            color: #4a4a4a;
            font-weight: 600;
            font-size: 1.1rem;
        }

        input[type="text"],
        input[type="password"],
        textarea,
        select {
            width: 100%;
            padding: 1rem;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: white;
        }

        input:focus,
        textarea:focus,
        select:focus {
            border-color: #667eea;
            outline: none;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }

        input[type="file"] {
            width: 100%;
            padding: 1rem;
            border: 2px dashed #e0e0e0;
            border-radius: 10px;
            background: white;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        input[type="file"]:hover {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }

        textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'Courier New', monospace;
        }

        .btn {
            display: block;
            width: 100%;
            padding: 1.2rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 1rem;
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: linear-gradient(135deg, #28a745, #20c997);
        }

        .btn-secondary:hover {
            box-shadow: 0 8px 20px rgba(40, 167, 69, 0.4);
        }

        .result {
            margin-top: 2rem;
            padding: 1.5rem;
            background: rgba(102, 126, 234, 0.1);
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }

        .error {
            background: rgba(220, 53, 69, 0.1);
            border-left-color: #dc3545;
            color: #721c24;
        }

        .success {
            background: rgba(40, 167, 69, 0.1);
            border-left-color: #28a745;
            color: #155724;
        }

        .key-display {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin-top: 1rem;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }

        .action-buttons {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1rem;
        }

        @media (max-width: 600px) {
            .container {
                margin: 1rem;
                padding: 1.5rem;
            }
            
            .tab-btn {
                padding: 0.8rem 1.5rem;
                font-size: 1rem;
            }
            
            h1 {
                font-size: 2rem;
            }

            .action-buttons {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Bảo Mật File & Ký Số</h1>
        
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('file-crypto')">📁 Mã Hóa File</button>
            <button class="tab-btn" onclick="switchTab('digital-sign')">✍️ Ký Số</button>
        </div>

        <!-- Tab Mã Hóa File -->
        <div id="file-crypto" class="tab-content active">
            <h2 style="margin-bottom: 1.5rem; color: #667eea;">Mã Hóa & Giải Mã File</h2>
            
            <form method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file">Chọn File:</label>
                    <input type="file" id="file" name="file" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Mật Khẩu (Khóa Mã Hóa):</label>
                    <input type="password" id="password" name="password" placeholder="Nhập mật khẩu bảo mật" required>
                </div>
                
                <div class="action-buttons">
                    <button type="submit" name="action" value="encrypt_file" class="btn">🔒 Mã Hóa File</button>
                    <button type="submit" name="action" value="decrypt_file" class="btn btn-secondary">🔓 Giải Mã File</button>
                </div>
            </form>
        </div>

        <!-- Tab Ký Số -->
        <div id="digital-sign" class="tab-content">
            <h2 style="margin-bottom: 1.5rem; color: #764ba2;">Ký Số & Xác Minh</h2>
            
            <form method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Chọn Hành Động:</label>
                    <select name="sign_action" onchange="toggleSignFields(this.value)">
                        <option value="generate_keys">Tạo Cặp Khóa RSA</option>
                        <option value="sign_data">Ký Số Dữ Liệu</option>
                        <option value="verify_signature">Xác Minh Chữ Ký</option>
                    </select>
                </div>

                <!-- Tạo khóa -->
                <div id="generate-section">
                    <button type="submit" name="action" value="generate_keys" class="btn">🔑 Tạo Cặp Khóa RSA</button>
                </div>

                <!-- Ký số -->
                <div id="sign-section" style="display: none;">
                    <div class="form-group">
                        <label for="data_to_sign">Dữ Liệu Cần Ký:</label>
                        <textarea name="data_to_sign" placeholder="Nhập văn bản cần ký số"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="private_key_sign">Private Key:</label>
                        <textarea name="private_key_sign" placeholder="Dán private key vào đây"></textarea>
                    </div>
                    <button type="submit" name="action" value="sign_data" class="btn">✍️ Ký Số</button>
                </div>

                <!-- Xác minh -->
                <div id="verify-section" style="display: none;">
                    <div class="form-group">
                        <label for="original_data">Dữ Liệu Gốc:</label>
                        <textarea name="original_data" placeholder="Nhập dữ liệu gốc"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="signature">Chữ Ký:</label>
                        <textarea name="signature" placeholder="Dán chữ ký vào đây"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="public_key_verify">Public Key:</label>
                        <textarea name="public_key_verify" placeholder="Dán public key vào đây"></textarea>
                    </div>
                    <button type="submit" name="action" value="verify_signature" class="btn btn-secondary">✅ Xác Minh</button>
                </div>
            </form>
        </div>

        {% if result %}
        <div class="result {{ result.type }}">
            <h3>{{ result.title }}</h3>
            {{ result.content | safe }}
        </div>
        {% endif %}
    </div>

    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById(tab).classList.add('active');
            event.target.classList.add('active');
        }

        function toggleSignFields(action) {
            document.getElementById('generate-section').style.display = action === 'generate_keys' ? 'block' : 'none';
            document.getElementById('sign-section').style.display = action === 'sign_data' ? 'block' : 'none';
            document.getElementById('verify-section').style.display = action === 'verify_signature' ? 'block' : 'none';
        }
    </script>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            if action == 'encrypt_file':
                file = request.files['file']
                password = request.form['password']
                
                if file and password:
                    file_data = file.read()
                    encrypted_data = encrypt_file_data(file_data, password)
                    
                    response = make_response(encrypted_data)
                    response.headers['Content-Type'] = 'application/octet-stream'
                    response.headers['Content-Disposition'] = f'attachment; filename=encrypted_{file.filename}'
                    return response
                    
            elif action == 'decrypt_file':
                file = request.files['file']
                password = request.form['password']
                
                if file and password:
                    encrypted_data = file.read()
                    decrypted_data = decrypt_file_data(encrypted_data, password)
                    
                    filename = file.filename
                    if filename.startswith('encrypted_'):
                        filename = filename[10:]  # Remove 'encrypted_' prefix
                    
                    response = make_response(decrypted_data)
                    response.headers['Content-Type'] = 'application/octet-stream'
                    response.headers['Content-Disposition'] = f'attachment; filename=decrypted_{filename}'
                    return response
                    
            elif action == 'generate_keys':
                private_key, public_key = generate_rsa_keys()
                result = {
                    'type': 'success',
                    'title': '🔑 Cặp Khóa RSA Đã Được Tạo',
                    'content': f'''
                        <p><strong>Private Key (Khóa Riêng):</strong></p>
                        <div class="key-display">{private_key.decode()}</div>
                        <p><strong>Public Key (Khóa Công Khai):</strong></p>
                        <div class="key-display">{public_key.decode()}</div>
                        <p style="margin-top: 1rem; color: #dc3545;"><strong>⚠️ Lưu ý:</strong> Hãy lưu trữ private key một cách an toàn!</p>
                    '''
                }
                
            elif action == 'sign_data':
                data = request.form['data_to_sign']
                private_key = request.form['private_key_sign']
                
                if data and private_key:
                    signature = sign_data(data.encode(), private_key.encode())
                    result = {
                        'type': 'success',
                        'title': '✍️ Chữ Ký Đã Được Tạo',
                        'content': f'''
                            <p><strong>Dữ liệu đã ký:</strong> {data}</p>
                            <p><strong>Chữ ký số:</strong></p>
                            <div class="key-display">{signature}</div>
                        '''
                    }
                    
            elif action == 'verify_signature':
                original_data = request.form['original_data']
                signature = request.form['signature']
                public_key = request.form['public_key_verify']
                
                if original_data and signature and public_key:
                    is_valid = verify_signature(original_data.encode(), signature, public_key.encode())
                    
                    if is_valid:
                        result = {
                            'type': 'success',
                            'title': '✅ Chữ Ký Hợp Lệ',
                            'content': '<p>Chữ ký được xác minh thành công! Dữ liệu không bị thay đổi.</p>'
                        }
                    else:
                        result = {
                            'type': 'error',
                            'title': '❌ Chữ Ký Không Hợp Lệ',
                            'content': '<p>Chữ ký không khớp hoặc dữ liệu đã bị thay đổi!</p>'
                        }
                        
        except Exception as e:
            result = {
                'type': 'error',
                'title': '❌ Lỗi',
                'content': f'<p>Đã xảy ra lỗi: {str(e)}</p>'
            }
    
    return render_template_string(html_template, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
