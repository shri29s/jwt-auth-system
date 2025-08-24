# JWT Authentication Service

A standalone Node.js authentication service with JWT tokens and MongoDB integration.

## 🚀 Quick Start

### Prerequisites

- Node.js 16+
- MongoDB running on `localhost:27017`

### Installation

```bash
npm install express jsonwebtoken bcrypt mongoose
node app.js
```

### Default Admin Account

- **Username**: `admin`
- **Password**: `admin123456`

## 📡 API Endpoints

| Method | Endpoint       | Description       | Auth Required |
| ------ | -------------- | ----------------- | ------------- |
| `GET`  | `/health`      | Service status    | ❌            |
| `POST` | `/register`    | Create account    | ❌            |
| `POST` | `/login`       | User login        | ❌            |
| `GET`  | `/profile`     | Get user profile  | ✅ JWT        |
| `GET`  | `/verify`      | Verify token      | ✅ JWT        |
| `GET`  | `/admin/users` | List all users    | ✅ Admin      |
| `GET`  | `/secret`      | Access secret key | ✅ Admin      |

## 🔐 Usage Examples

### Register User

```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john", "password":"password123", "email":"john@example.com"}'
```

### Login

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"admin123456"}'
```

### Access Protected Resource

```bash
curl -X GET http://localhost:3000/secret \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🎯 Quick Secret Access

1. **Login as admin**: `POST /login` with `admin/admin123456`
2. **Copy JWT token** from response
3. **Access secret**: `GET /secret` with `Authorization: Bearer TOKEN`
4. **Get secret key**: `HIDDEN_TREASURE_2024_AUTHENTICATED_ACCESS`

## 📁 Postman Collection

Import this collection for easy testing:

- Base URL: `http://localhost:3000`
- Auto-saves JWT tokens
- Includes all endpoints

## ⚙️ Environment Variables

```bash
JWT_SECRET=your-secret-key-here
MONGODB_URI=mongodb://localhost:27017/auth_service
NODE_ENV=production
```

## 📦 Dependencies

```json
{
  "express": "^4.18.0",
  "jsonwebtoken": "^9.0.0",
  "bcrypt": "^5.1.0",
  "mongoose": "^7.0.0"
}
```

## 🔒 Security Features

- ✅ Password hashing (bcrypt)
- ✅ JWT tokens (1-hour expiry)
- ✅ Role-based access control
- ✅ Input validation
- ✅ MongoDB integration

## 🛠️ Development

```bash
# Start MongoDB (Docker)
docker run -d -p 27017:27017 mongo

# Start service
node app.js

# Service runs on http://localhost:3000
```

## 📖 API Response Examples

### Login Response

```json
{
  "message": "Login successful",
  "user": {
    "id": "...",
    "username": "admin",
    "role": "admin"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Secret Response

```json
{
  "message": "🔐 Secret Access Granted!",
  "secretKey": "HIDDEN_TREASURE_2024_AUTHENTICATED_ACCESS",
  "user": "admin"
}
```

---

**🔐 Secret Key**: `HIDDEN_TREASURE_2024_AUTHENTICATED_ACCESS`
