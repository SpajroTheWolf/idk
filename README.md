# API do logowania i tworzenia kont - Dokumentacja

## Cechy bezpieczeństwa

✓ Haszowanie haseł z bcrypt (12 rounds)
✓ Wymuszenie mocnego hasła (duże litery, małe litery, cyfry, minimum 8 znaków)
✓ Walidacja nazwy użytkownika
✓ Rate limiting (ograniczenie liczby żądań na IP)
✓ Unikalny klucz API dla każdego użytkownika (UUID4)
✓ Bezpieczna weryfikacja hasła
✓ CORS (kontrola żądań cross-origin)

## Instalacja (lokal)

```bash
pip install -r requirements.txt
```

## Uruchomienie (lokal)

```bash
python main.py
```

API będzie dostępne na http://localhost:5000

## Deployment na Render

### 1. Przygotowanie GitHub
- Wrzuć projekt na GitHub
- Upewnij się, że folder `/api` zawiera:
  - `main.py`
  - `requirements.txt`
  - `Procfile`
  - `render.yaml`

### 2. Tworzenie usługi na Render

**Opcja A - Automatycznie z `render.yaml`:**
1. Idź na https://render.com
2. Kliknij "New +" → "Web Service"
3. Połącz swoje GitHub
4. Wybierz repozytorium
5. Render automatycznie przeczyta `render.yaml`
6. Kliknij "Deploy"

**Opcja B - Ręczna konfiguracja:**
1. https://render.com → "New +" → "Web Service"
2. Podłącz GitHub
3. Wybierz repozytorium
4. Ustaw:
   - **Name:** `spajro-midi-api`
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn main:app`
5. Zmienne środowiskowe (Environment):
   ```
   FLASK_ENV = production
   PYTHON_VERSION = 3.10.0
   ```
6. Wybierz plan (darmowy Starter wystarczy do testów)
7. Kliknij "Create Web Service"

### 3. Zmienne środowiskowe na Render

W panelu Render dla usługi:
- Settings → Environment
- Dodaj zmienne:
  ```
  FLASK_ENV = production
  PYTHON_VERSION = 3.10.0
  ```
- `SECRET_KEY` będzie wygenerowany automatycznie (jeśli użyjesz render.yaml)

### 4. Po deplojmencie

- Render da ci URL (np. `https://spajro-midi-api.onrender.com`)
- API będzie dostępne na:
  - `https://spajro-midi-api.onrender.com/health`
  - `https://spajro-midi-api.onrender.com/api/register`
  - etc.

**⚠️ Ważne:** Darmowe instancje Renderu mogą się „uśpić" po 15 minutach bezczynności. Wznowienie trwa ~30 sekund.

## Endpointy

### 1. GET /health
Sprawdzenie czy API działa

**Odpowiedź:**
```json
{
  "status": "ok",
  "message": "API jest aktywne"
}
```

### 2. POST /api/register
**Rejestracja nowego konta**

**Żądanie:**
```json
{
  "username": "kowalski123",
  "password": "Haslo@123"
}
```

**Wymagania hasła:**
- Minimum 8 znaków
- Przynajmniej jedna duża litera
- Przynajmniej jedna mała litera
- Przynajmniej jedna cyfra

**Pomyślna odpowiedź (201):**
```json
{
  "success": true,
  "username": "kowalski123",
  "api_key": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Konto stworzono pomyślnie"
}
```

**Błędy (400):**
```json
{
  "success": false,
  "message": "Nazwa użytkownika już istnieje"
}
```

### 3. POST /api/login
**Logowanie**

**Żądanie:**
```json
{
  "username": "kowalski123",
  "password": "Haslo@123",
  "api_key": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Pomyślna odpowiedź (200):**
```json
{
  "success": true,
  "username": "kowalski123",
  "api_key": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-03-28 10:30:45",
  "last_login": "2026-03-28T10:35:20.123456",
  "message": "Zalogowano pomyślnie"
}
```

**Błędy (401):**
```json
{
  "success": false,
  "message": "Nieprawidłowe hasło"
}
```

### 4. POST /api/validate-key
**Walidacja klucza API**

**Żądanie:**
```json
{
  "api_key": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Pomyślna odpowiedź (200):**
```json
{
  "success": true,
  "username": "kowalski123",
  "message": "Klucz API jest prawidłowy"
}
```

**Błędy (401):**
```json
{
  "success": false,
  "message": "Klucz API jest nieprawidłowy"
}
```

## Rate Limiting

- `/register` - max 3 żądania na IP w 60 sekund
- `/login` - max 5 żądań na IP w 60 sekund
- `/validate-key` - max 10 żądań na IP w 60 sekund

Odpowiedź przy przekroczeniu (429):
```json
{
  "success": false,
  "message": "Zbyt wiele żądań. Spróbuj ponownie za chwilę"
}
```

## Baza danych

API używa SQLite3 (plik `users.db`). Tabela `users` zawiera:
- id: unikalny identyfikator
- username: nazwa użytkownika (unikalna)
- password_hash: zahaszowane hasło
- api_key: unikalny klucz API (UUID4)
- created_at: data utworzenia konta
- last_login: data ostatniego logowania

## Przykład klienta (Python)

```python
import requests

BASE_URL = "http://localhost:5000"

# Rejestracja
resp = requests.post(f"{BASE_URL}/api/register", json={
    "username": "kowalski123",
    "password": "Haslo@123"
})
api_key = resp.json()["api_key"]

# Logowanie
resp = requests.post(f"{BASE_URL}/api/login", json={
    "username": "kowalski123",
    "password": "Haslo@123",
    "api_key": api_key
})
print(resp.json())

# Walidacja klucza
resp = requests.post(f"{BASE_URL}/api/validate-key", json={
    "api_key": api_key
})
print(resp.json())
```

## Uwagi bezpieczeństwa dla produkcji

1. Zmień `SECRET_KEY` w `.env` na losowy, bezpieczny klucz
2. Przenieś bazę danych do bezpiecznego miejsca
3. Użyj HTTPS zamiast HTTP
4. Dodaj uwierzytelnianie admin-panelu
5. Rozważ dodanie email verifikacji
6. Implementuj log błędów
7. Zwiększ rate limiting w produkcji
8. Dodaj backup bazy danych
9. Monitoruj aktywność logowania
