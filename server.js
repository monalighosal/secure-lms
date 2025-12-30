const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const config = require('./config');
const security = require('./security');

const app = express();
const PORT = config.PORT;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Serve CSS file
app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'style.css'));
});

// Set up SQLite database
const db = new sqlite3.Database('./lms.db');

// Initialize the database and create tables
function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'student',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`);

      // Courses table
      db.run(`CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        instructor_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`);

      // Enrollments table for access control
      db.run(`CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        course_id INTEGER,
        enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (course_id) REFERENCES courses (id),
        UNIQUE(user_id, course_id)
      )`);

      // Lessons table
      db.run(`CREATE TABLE IF NOT EXISTS lessons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT NOT NULL,
        content TEXT,
        order_num INTEGER,
        FOREIGN KEY (course_id) REFERENCES courses (id)
      )`);

      // Assignments table
      db.run(`CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        due_date DATETIME,
        FOREIGN KEY (course_id) REFERENCES courses (id)
      )`);

      // User progress table
      db.run(`CREATE TABLE IF NOT EXISTS user_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        lesson_id INTEGER,
        completed BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (lesson_id) REFERENCES lessons (id)
      )`);

      // Certificates table
      db.run(`CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        course_id INTEGER,
        issued_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        certificate_code TEXT UNIQUE,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (course_id) REFERENCES courses (id)
      )`);

      // User preferences table
      db.run(`CREATE TABLE IF NOT EXISTS user_preferences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        preferences TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )`);

      // Comments table
      db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        author_id INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (author_id) REFERENCES users (id)
      )`);
      
      // Call the callback when all tables are created
      resolve();
    });
  });
}

// Initialize database and then set up routes
initializeDatabase().then(() => {
  console.log('Database initialized successfully');
  
  // Middleware to check if user is logged in
  function isLoggedIn(req, res, next) {
    if (req.session.user) {
      next();
    } else {
      res.redirect('/login');
    }
  }

  // Get current user info
  app.get('/api/user', isLoggedIn, (req, res) => {
    // Return current user info
    res.json({
      id: req.session.user.id,
      username: req.session.user.username,
      email: req.session.user.email,
      role: req.session.user.role
    });
  });

  // Routes

  // Home page
  app.get('/', (req, res) => {
    if (req.session.user) {
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  });

  // Login page
  app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });

  // Login route - with SQL injection protection
  app.post('/login', (req, res) => {
    let { username, password } = req.body;
    
    // Always use parameterized queries to prevent SQL injection
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    
    db.get(query, [username, password], (err, user) => {
      if (err) {
        // Don't expose internal error details
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (user) {
        req.session.user = user;
        res.redirect(`/dashboard/${user.id}`);
      } else {
        res.status(401).send('Invalid credentials');
      }
    });
  });

  // Registration page
  app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
  });

  // Registration route - with SQL injection protection
  app.post('/register', (req, res) => {
    let { username, password, email } = req.body;
    
    // Always use parameterized queries to prevent SQL injection
    const query = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
    
    db.run(query, [username, password, email], function(err) {
      if (err) {
        // Don't expose internal error details
        console.error('Registration error:', err);
        return res.status(500).json({ error: 'Registration failed' });
      }
      
      // Redirect to login after registration
      res.redirect('/login');
    });
  });

  // Dashboard - user-specific with access control
  app.get('/dashboard/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Always check if user has access to this dashboard
    if (!security.validateUserAccess(req, userId)) {
      return res.redirect('/error');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
  });

  // Dashboard redirect for backward compatibility
  app.get('/dashboard', isLoggedIn, (req, res) => {
    res.redirect(`/dashboard/${req.session.user.id}`);
  });

  // Courses page
  app.get('/courses', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'courses.html'));
  });

  // Get all courses
  app.get('/api/courses', isLoggedIn, (req, res) => {
    db.all('SELECT * FROM courses', (err, courses) => {
      if (err) {
        // Don't expose internal error details
        console.error('Courses access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(courses);
    });
  });

  // Get specific course by ID - with access control
  app.get('/api/courses/:id', isLoggedIn, (req, res) => {
    const courseId = req.params.id;
    
    // Check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the course
      db.get('SELECT * FROM courses WHERE id = ?', [courseId], (err, course) => {
        if (err) {
          // Don't expose internal error details
          console.error('Course access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!course) {
          return res.status(404).json({ error: 'Course not found' });
        }
        
        res.json(course);
      });
    });
  });

  // Get lessons for a course - with access control
  app.get('/api/courses/:courseId/lessons', isLoggedIn, (req, res) => {
    const courseId = req.params.courseId;
    
    // Check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the lessons
      db.all('SELECT * FROM lessons WHERE course_id = ?', [courseId], (err, lessons) => {
        if (err) {
          // Don't expose internal error details
          console.error('Lessons access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(lessons);
      });
    });
  });

  // Get assignments for a course - with access control
  app.get('/api/courses/:courseId/assignments', isLoggedIn, (req, res) => {
    const courseId = req.params.courseId;
    
    // Check if user has access to the course
    security.validateCourseAccess(req, courseId, db, (hasAccess) => {
      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // User has access, return the assignments
      db.all('SELECT * FROM assignments WHERE course_id = ?', [courseId], (err, assignments) => {
        if (err) {
          // Don't expose internal error details
          console.error('Assignments access error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(assignments);
      });
    });
  });

  // Get user progress - with access control
  app.get('/api/progress/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Always check if user has access to this progress data
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // User has access, return the progress
    db.all('SELECT * FROM user_progress WHERE user_id = ?', [userId], (err, progress) => {
      if (err) {
        // Don't expose internal error details
        console.error('Progress access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json(progress);
    });
  });

  // User profile page - with access control
  app.get('/user/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Always check if user has access to this profile
    if (!security.validateUserAccess(req, userId)) {
      return res.redirect('/error');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'user-profile.html'));
  });

  // Get user profile data - with access control
  app.get('/api/users/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Always check if user has access to this user's data
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    db.get('SELECT id, username, email, role, created_at FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) {
        // Don't expose internal error details
        console.error('User data access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(user);
    });
  });

  // Update user profile - with access control and mass assignment protection
  app.put('/api/users/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Always check if user has access to update this profile
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Sanitize and validate the updates
    const sanitizedUpdates = security.validateProfileUpdate(req, req.body);
    
    // Build the query dynamically based on the fields to update
    const fields = Object.keys(sanitizedUpdates);
    if (fields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => sanitizedUpdates[field]);
    values.push(userId); // For the WHERE clause
    
    const query = `UPDATE users SET ${setClause} WHERE id = ?`;
    
    db.run(query, values, function(err) {
      if (err) {
        // Don't expose internal error details
        console.error('Profile update error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json({ message: 'Profile updated successfully' });
    });
  });

  // Admin panel - with access control
  app.get('/admin', isLoggedIn, (req, res) => {
    // Always check if user is actually an admin, regardless of config mode
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.redirect('/error');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  });

  // Get all users - admin only
  app.get('/api/admin/users', isLoggedIn, (req, res) => {
    // Always check if user is actually an admin, regardless of config mode
    if (!security.isAdmin(req)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    db.all('SELECT id, username, email, role, created_at FROM users ORDER BY id', (err, users) => {
      if (err) {
        // Don't expose internal error details
        console.error('Admin users access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json(users);
    });
  });

  // Get all courses - admin only
  app.get('/api/admin/courses', isLoggedIn, (req, res) => {
    // Always check if user is actually an admin, regardless of config mode
    if (!security.isAdmin(req)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    db.all(`SELECT c.*, u.username as instructor_name FROM courses c LEFT JOIN users u ON c.instructor_id = u.id ORDER BY c.id`, (err, courses) => {
      if (err) {
        // Don't expose internal error details
        console.error('Admin courses access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json(courses);
    });
  });

  // Preferences page
  app.get('/preferences', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'preferences.html'));
  });

  // Get user preferences - with access control
  app.get('/api/preferences', isLoggedIn, (req, res) => {
    // Always check if user is accessing their own preferences
    if (!security.validateUserAccess(req, req.session.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    db.get('SELECT preferences FROM user_preferences WHERE user_id = ?', [req.session.user.id], (err, result) => {
      if (err) {
        // Don't expose internal error details
        console.error('Preferences access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json({ preferences: result ? result.preferences : '{}' });
    });
  });

  // Update user preferences - with access control
  app.post('/api/preferences', isLoggedIn, (req, res) => {
    // Always check if user is updating their own preferences
    if (!security.validateUserAccess(req, req.session.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    let { preferences } = req.body;
    
    // Validate and sanitize the preferences input
    try {
      // Use the safeParse function to prevent prototype pollution
      const parsedPrefs = security.safeParse(preferences);
      preferences = JSON.stringify(parsedPrefs);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid preferences format' });
    }
    
    // Insert or update the preferences
    const query = `INSERT OR REPLACE INTO user_preferences (user_id, preferences) VALUES (?, ?)`;
    
    db.run(query, [req.session.user.id, preferences], function(err) {
      if (err) {
        // Don't expose internal error details
        console.error('Preferences update error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      res.json({ message: 'Preferences updated successfully' });
    });
  });

  // Logout
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
  });

  // Get comments for a user
  app.get('/api/comments/:userId', isLoggedIn, (req, res) => {
    const userId = req.params.userId;
    
    // Check if user has access to this user's comments
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Return comments for this user from database
    const query = `SELECT c.id, c.content, c.created_at, u.username as author FROM comments c JOIN users u ON c.author_id = u.id WHERE c.user_id = ? ORDER BY c.created_at DESC`;
    
    db.all(query, [userId], (err, comments) => {
      if (err) {
        console.error('Comments access error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(comments);
    });
  });

  // Add comment for a user
  app.post('/api/comments', isLoggedIn, (req, res) => {
    const { userId, content } = req.body;
    
    // Check if user has access to add comments for this user
    if (!security.validateUserAccess(req, userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Insert the comment into database (with XSS patch - sanitizing content)
    const query = `INSERT INTO comments (user_id, author_id, content) VALUES (?, ?, ?)`;
    
    db.run(query, [userId, req.session.user.id, security.sanitizeHTML(content)], function(err) {
      if (err) {
        console.error('Comment insertion error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ message: 'Comment added successfully', commentId: this.lastID });
    });
  });

  // Error page route
  app.get('/error', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'error.html'));
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});

// Handle database initialization error
initializeDatabase().catch(err => {
  console.error('Database initialization failed:', err);
  process.exit(1);
});