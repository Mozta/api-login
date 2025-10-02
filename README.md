# API Login - Flask Authentication System

A Flask-based REST API that provides user authentication functionality using JWT tokens. This API supports user registration, login, token refresh, and protected routes.

## Features

- User registration with email validation
- User login with secure password hashing
- JWT-based authentication with access and refresh tokens
- Token refresh mechanism
- Protected user profile endpoint
- Email normalization and validation
- Secure password requirements
- SQLite database with SQLAlchemy ORM

## Technology Stack

- **Framework**: Flask 3.1.2
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: JWT tokens using Flask-JWT-Extended
- **Password Hashing**: Werkzeug security utilities
- **Email Validation**: email-validator library
- **Environment Management**: python-dotenv

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd api-login
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory:
```env
DATABASE_URL=sqlite:///site.db
JWT_SECRET_KEY=your-super-secret-key-here
ACCESS_TOKEN_EXPIRES=15
REFRESH_TOKEN_EXPIRES_DAYS=7
```

5. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## Environment Variables

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `DATABASE_URL` | Database connection string | `sqlite:///site.db` |
| `JWT_SECRET_KEY` | Secret key for JWT token signing | `super-secret` |
| `ACCESS_TOKEN_EXPIRES` | Access token expiration time in minutes | `15` |
| `REFRESH_TOKEN_EXPIRES_DAYS` | Refresh token expiration time in days | `7` |

## API Endpoints

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "securepassword123"
}
```

**Response (201 Created):**
```json
{
    "message": "Usuario registrado exitosamente.",
    "user": {
        "id": 1,
        "username": "johndoe",
        "email": "john@example.com",
        "created_at": "2025-10-02T10:30:00"
    },
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Login User
```http
POST /auth/login
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "securepassword123"
}
```

**Response (200 OK):**
```json
{
    "message": "Login exitoso.",
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Refresh Token
```http
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

**Response (200 OK):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Protected Endpoints

#### Get User Profile
```http
GET /profile
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
    "user": {
        "id": 1,
        "username": "johndoe",
        "email": "john@example.com",
        "created_at": "2025-10-02T10:30:00"
    }
}
```

## Error Responses

The API returns consistent error responses in the following format:

```json
{
    "error": "Error message description"
}
```

### Common Error Codes

- `400 Bad Request`: Missing required fields, invalid email format, password too short
- `401 Unauthorized`: Invalid credentials, expired or invalid token
- `404 Not Found`: User not found
- `409 Conflict`: Email already registered

## Validation Rules

### User Registration
- **Username**: Required, must be unique
- **Email**: Required, must be valid email format, must be unique
- **Password**: Required, minimum 6 characters

### Email Validation
- Emails are normalized (lowercased, trimmed)
- Email format validation using the `email-validator` library
- Deliverability checking is disabled for performance

## Security Features

- Passwords are hashed using Werkzeug's secure password hashing
- JWT tokens with configurable expiration times
- Separate access and refresh tokens
- Email normalization to prevent duplicate accounts
- No sensitive information exposed in error messages
- CORS protection (can be configured as needed)

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Development

### Project Structure
```
api-login/
├── app.py              # Main Flask application
├── models.py           # Database models
├── requirements.txt    # Python dependencies
├── .env               # Environment variables (create this)
├── instance/
│   └── site.db        # SQLite database file
└── __pycache__/       # Python cache files
```

### Running in Development Mode
The application runs in debug mode by default when started with `python app.py`. This enables:
- Automatic reloading on code changes
- Detailed error messages
- Debug toolbar (if configured)

### Database Management
The database is automatically created when the application starts. To reset the database, simply delete the `instance/site.db` file and restart the application.

## Production Considerations

1. **Security**:
   - Change the `JWT_SECRET_KEY` to a strong, randomly generated secret
   - Use a production database (PostgreSQL, MySQL)
   - Enable HTTPS
   - Configure proper CORS settings

2. **Performance**:
   - Use a production WSGI server (Gunicorn, uWSGI)
   - Configure database connection pooling
   - Implement rate limiting
   - Add caching where appropriate

3. **Monitoring**:
   - Add logging
   - Implement health check endpoints
   - Monitor token usage and security events

## License

This project is licensed under the MIT License - see the LICENSE file for details.