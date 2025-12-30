# Secure Learning Management System (Secure-LMS)

A secure Learning Management System designed to demonstrate and teach web application security concepts. This application showcases proper security implementations to protect against common vulnerabilities like SQL injection, XSS, IDOR, and more.

## Table of Contents
- [Features](#features)
- [Security Measures](#security-measures)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Security Features Details](#security-features-details)
- [Troubleshooting](#troubleshooting)

## Features

- User authentication and authorization
- Course management system
- User profiles and dashboards
- Comment functionality with XSS protection
- Admin panel with user management
- Secure session management
- Input validation and sanitization

## Security Measures

- SQL injection prevention
- Cross-Site Scripting (XSS) protection
- Insecure Direct Object Reference (IDOR) prevention
- Prototype pollution prevention
- Session management security
- Access control enforcement
- Input sanitization

## Dependencies

The application requires the following dependencies:

- Node.js (v14 or higher)
- npm (Node Package Manager)
- SQLite3 (database)

### Core Dependencies:
- `express`: Web framework
- `sqlite3`: Database driver
- `express-session`: Session management
- `body-parser`: Request body parsing
- `cookie-parser`: Cookie handling
- `cors`: Cross-origin resource sharing

## Installation

1. Clone or download the project
2. Navigate to the project directory
3. Install dependencies:
   ```bash
   npm install
   ```

## Usage

### Running the Application

Start the application in secure mode:
```bash
npm start
```

The application will start on `http://localhost:5001` by default.

### Default Credentials

The application comes with sample users for testing:
- Admin: `admin` / `password123`
- Student: `student1` / `studentpass`
- Instructor: `instructor1` / `instructorpass`

## API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Login endpoint
- `GET /register` - Registration page
- `POST /register` - Registration endpoint
- `GET /logout` - Logout endpoint

### User Management
- `GET /dashboard` - User dashboard
- `GET /dashboard/:userId` - Specific user dashboard
- `GET /user/:userId` - User profile page
- `GET /api/users/:userId` - Get user data
- `PUT /api/users/:userId` - Update user profile

### Course Management
- `GET /courses` - Course listing
- `GET /api/courses` - Get all courses
- `GET /api/courses/:id` - Get specific course
- `GET /api/courses/:courseId/lessons` - Get lessons for a course
- `GET /api/courses/:courseId/assignments` - Get assignments for a course

### Comments
- `GET /api/comments/:userId` - Get comments for a user
- `POST /api/comments` - Add comment for a user

### Admin Panel
- `GET /admin` - Admin panel (admin access only)
- `GET /api/admin/users` - Get all users (admin only)
- `GET /api/admin/courses` - Get all courses (admin only)

### Other Endpoints
- `GET /preferences` - User preferences page
- `GET /api/preferences` - Get user preferences
- `POST /api/preferences` - Update user preferences
- `GET /api/user` - Get current user info

## Security Features Details

### SQL Injection Prevention
All database queries use parameterized queries to prevent SQL injection attacks:
```javascript
const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
db.get(query, [username, password], callback);
```

### XSS Prevention
Input sanitization is performed using the `sanitizeHTML` function:
- Server-side sanitization of all user inputs
- Safe DOM manipulation using `textContent` instead of `innerHTML`
- Removal of dangerous HTML tags and attributes

### IDOR Protection
Access control checks ensure users can only access their own data:
```javascript
function validateUserAccess(req, userId) {
  return req.session.user && (req.session.user.id == userId || req.session.user.role === 'admin');
}
```

### Prototype Pollution Prevention
Safe JSON parsing that prevents prototype pollution attacks by validating input properties.

### Session Management
Secure session handling with proper validation and destruction on logout.

## Troubleshooting

### Common Issues

1. **Port already in use**
   - Error: `EADDRINUSE: address already in use :::5001`
   - Solution: Check for running processes on port 5001 and terminate them:
     ```bash
     # Windows
     netstat -ano | findstr :5001
     taskkill /f /pid <PID>
     ```

2. **Database initialization errors**
   - Ensure the application has write permissions to the project directory
   - Run `node init-db.js` manually to initialize the database

3. **Cannot access the application**
   - Verify the server is running on http://localhost:5001
   - Check firewall settings if accessing from another machine
   - Try clearing browser cache

### Development Mode
For development with auto-restart:
```bash
npm run dev
```

## Project Structure

```
secure-lms/
├── public/                 # HTML, CSS, client-side JS
│   ├── admin.html
│   ├── courses.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── user-profile.html
│   ├── user-dashboard.html
│   └── style.css
├── server.js              # Main application server
├── security.js            # Security functions
├── config.js              # Configuration settings
├── init-db.js             # Database initialization
├── lms.db                 # SQLite database file
└── package.json           # Dependencies and scripts
```

## Contributing

This project is designed for educational purposes. Contributions that improve security implementations or add new security demonstrations are welcome.

## License

This project is for educational purposes only.

## Security Testing

This application demonstrates proper security implementations. For educational purposes, it shows the difference between secure and vulnerable code implementations.