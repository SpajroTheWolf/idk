import os
import bcrypt
import uuid
import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
from typing import Tuple, Dict, Any
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
CORS(app)
app.config['JSON_SORT_KEYS'] = False

# Konfiguracja bazy danych - PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    # Dla testów lokalnych
    DATABASE_URL = "postgresql://localhost/users_db"

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# ==================== INICJALIZACJA BAZY DANYCH ====================

def get_db_connection():
    """Zwraca połączenie z bazą danych"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.Error as e:
        print(f"Błąd połączenia z bazą: {e}")
        return None

def init_db():
    """Inicjalizuje bazę danych"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT NULL
            )
        ''')
        conn.commit()
        c.close()
        conn.close()
        return True
    except psycopg2.Error as e:
        print(f"Błąd inicjalizacji bazy danych: {e}")
        return False

# Middleware do inicjalizacji bazy przy każdym żądaniu
@app.before_request
def ensure_db():
    """Upewnia się że baza danych istnieje"""
    init_db()

# ==================== WALIDACJA ====================

def validate_username(username: str) -> Tuple[bool, str]:
    """Waliduje nazwę użytkownika"""
    if not username or len(username) < 3:
        return False, "Nazwa użytkownika musi mieć co najmniej 3 znaki"
    if len(username) > 50:
        return False, "Nazwa użytkownika nie może być dłuższa niż 50 znaków"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Nazwa użytkownika może zawierać tylko litery, cyfry, - i _"
    return True, ""

def validate_password(password: str) -> Tuple[bool, str]:
    """Waliduje hasło"""
    if not password:
        return False, "Hasło jest wymagane"
    if len(password) < 8:
        return False, "Hasło musi mieć co najmniej 8 znaków"
    if len(password) > 128:
        return False, "Hasło jest za długie (max 128 znaków)"
    
    # Wymagania bezpieczeństwa
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
    
    if not (has_upper and has_lower and has_digit):
        return False, "Hasło musi zawierać: duże litery, małe litery i cyfry"
    
    return True, ""

# ==================== HASZOWANIE HASEŁ ====================

def hash_password(password: str) -> str:
    """Haszuje hasło"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Weryfikuje hasło"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_api_key() -> str:
    """Generuje unikalny klucz API"""
    return str(uuid.uuid4())

# ==================== OPERACJE NA BAZIE DANYCH ====================

def user_exists(username: str) -> bool:
    """Sprawdza czy użytkownik istnieje"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = %s', (username,))
        result = c.fetchone()
        c.close()
        conn.close()
        return result is not None
    except psycopg2.Error:
        return False

def create_user(username: str, password: str) -> Dict[str, Any]:
    """Tworzy nowego użytkownika"""
    try:
        password_hash = hash_password(password)
        api_key = generate_api_key()
        
        conn = get_db_connection()
        if not conn:
            return {'success': False, 'message': 'Błąd połączenia z bazą'}
        
        c = conn.cursor()
        c.execute('''
            INSERT INTO users (username, password_hash, api_key)
            VALUES (%s, %s, %s)
        ''', (username, password_hash, api_key))
        conn.commit()
        c.close()
        conn.close()
        
        return {
            'success': True,
            'username': username,
            'api_key': api_key,
            'message': 'Konto stworzono pomyślnie'
        }
    except psycopg2.IntegrityError:
        return {
            'success': False,
            'message': 'Nazwa użytkownika już istnieje'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Błąd: {str(e)}'
        }

def authenticate_user(username: str, password: str, api_key: str) -> Dict[str, Any]:
    """Autentykuje użytkownika"""
    try:
        conn = get_db_connection()
        if not conn:
            return {'success': False, 'message': 'Błąd połączenia z bazą'}
        
        c = conn.cursor()
        c.execute('''
            SELECT id, username, password_hash, api_key, created_at, last_login
            FROM users WHERE username = %s
        ''', (username,))
        user = c.fetchone()
        
        if not user:
            c.close()
            conn.close()
            return {
                'success': False,
                'message': 'Użytkownik nie istnieje'
            }
        
        user_id, stored_username, password_hash, stored_api_key, created_at, last_login = user
        
        # Sprawdzenie hasła
        if not verify_password(password, password_hash):
            c.close()
            conn.close()
            return {
                'success': False,
                'message': 'Nieprawidłowe hasło'
            }
        
        # Sprawdzenie klucza API
        if api_key != stored_api_key:
            c.close()
            conn.close()
            return {
                'success': False,
                'message': 'Nieprawidłowy klucz API'
            }
        
        # Aktualizacja last_login
        c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s', (user_id,))
        conn.commit()
        c.close()
        conn.close()
        
        return {
            'success': True,
            'username': stored_username,
            'api_key': stored_api_key,
            'created_at': created_at.isoformat() if created_at else None,
            'last_login': datetime.now().isoformat(),
            'message': 'Zalogowano pomyślnie'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Błąd: {str(e)}'
        }

# ==================== RATE LIMITING ====================

request_counts = {}

def rate_limit(max_requests: int = 5, window: int = 60):
    """Dekorator do ograniczenia liczby żądań"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = datetime.now().timestamp()
            
            if ip not in request_counts:
                request_counts[ip] = []
            
            # Usuń stare żądania
            request_counts[ip] = [timestamp for timestamp in request_counts[ip] 
                                  if now - timestamp < window]
            
            if len(request_counts[ip]) >= max_requests:
                return jsonify({
                    'success': False,
                    'message': 'Zbyt wiele żądań. Spróbuj ponownie za chwilę'
                }), 429
            
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== ENDPOINTY API ====================

@app.route('/health', methods=['GET'])
def health():
    """Sprawdzenie czy API działa"""
    return jsonify({
        'status': 'ok',
        'message': 'API jest aktywne'
    }), 200

@app.route('/api/register', methods=['POST'])
@rate_limit(max_requests=3, window=60)
def register():
    """
    Endpoint do rejestracji nowego konta
    
    Wymagane pola JSON:
    - username (str): nazwa użytkownika
    - password (str): hasło
    
    Zwraca:
    - 201: Konto stworzono pomyślnie
    - 400: Błąd walidacji lub username już istnieje
    - 429: Zbyt wiele żądań
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Wymagane dane JSON'
            }), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Walidacja username
        valid_username, error_msg = validate_username(username)
        if not valid_username:
            return jsonify({
                'success': False,
                'message': error_msg
            }), 400
        
        # Walidacja password
        valid_password, error_msg = validate_password(password)
        if not valid_password:
            return jsonify({
                'success': False,
                'message': error_msg
            }), 400
        
        # Sprawdzenie czy username już istnieje
        if user_exists(username):
            return jsonify({
                'success': False,
                'message': 'Nazwa użytkownika już istnieje'
            }), 400
        
        # Tworzenie użytkownika
        result = create_user(username, password)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window=60)
def login():
    """
    Endpoint do logowania
    
    Wymagane pola JSON:
    - username (str): nazwa użytkownika
    - password (str): hasło
    - api_key (str): klucz API
    
    Zwraca:
    - 200: Zalogowano pomyślnie
    - 401: Błędy autentykacji
    - 400: Brakujące dane
    - 429: Zbyt wiele żądań
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Wymagane dane JSON'
            }), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        api_key = data.get('api_key', '').strip()
        
        if not username or not password or not api_key:
            return jsonify({
                'success': False,
                'message': 'Wymagane pola: username, password, api_key'
            }), 400
        
        result = authenticate_user(username, password, api_key)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 401
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@app.route('/api/validate-key', methods=['POST'])
@rate_limit(max_requests=10, window=60)
def validate_key():
    """
    Endpoint do walidacji klucza API
    
    Wymagane pola JSON:
    - api_key (str): klucz API do walidacji
    
    Zwraca:
    - 200: Klucz jest prawidłowy
    - 401: Klucz jest nieprawidłowy
    - 400: Brakujące dane
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Wymagane dane JSON'
            }), 400
        
        api_key = data.get('api_key', '').strip()
        
        if not api_key:
            return jsonify({
                'success': False,
                'message': 'Wymagane pole: api_key'
            }), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({
                'success': False,
                'message': 'Błąd połączenia z bazą'
            }), 500
        
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE api_key = %s', (api_key,))
        user = c.fetchone()
        c.close()
        conn.close()
        
        if user:
            return jsonify({
                'success': True,
                'username': user[0],
                'message': 'Klucz API jest prawidłowy'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Klucz API jest nieprawidłowy'
            }), 401
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Błąd serwera: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Handler dla nieznalezionych endpointów"""
    return jsonify({
        'success': False,
        'message': 'Endpoint nie znaleziony'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handler dla niedozwolonych metod HTTP"""
    return jsonify({
        'success': False,
        'message': 'Metoda HTTP niedozwolona'
    }), 405

# ==================== URUCHOMIENIE ====================

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print("✓ Baza danych zainicjalizowana")
    print(f"✓ API uruchamiane na http://{host}:{port}")
    print("\nEndpointy:")
    print("  GET  /health                 - Sprawdzenie statusu")
    print("  POST /api/register           - Rejestracja nowego konta")
    print("  POST /api/login              - Logowanie")
    print("  POST /api/validate-key       - Walidacja klucza API")
    app.run(debug=debug, host=host, port=port)
