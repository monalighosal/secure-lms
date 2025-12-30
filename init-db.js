const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./lms.db');

// Create tables and insert sample data
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

  // Insert sample users
  const users = [
    ['admin', 'password123', 'admin@vulnerable-lms.com', 'admin'],
    ['student1', 'studentpass', 'student1@example.com', 'student'],
    ['student2', 'studentpass', 'student2@example.com', 'student'],
    ['instructor1', 'instructorpass', 'instructor1@example.com', 'instructor']
  ];

  const stmt = db.prepare('INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)');
  users.forEach(user => {
    stmt.run(user);
  });
  stmt.finalize();

  // Insert sample courses
  const courses = [
    ['Web Security Fundamentals', 'Learn the basics of web application security', 4],
    ['SQL Injection Deep Dive', 'Explore SQL injection techniques in depth', 4],
    ['Authentication Security', 'Understand authentication mechanisms and flaws', 4]
  ];

  const courseStmt = db.prepare('INSERT OR IGNORE INTO courses (title, description, instructor_id) VALUES (?, ?, ?)');
  courses.forEach(course => {
    courseStmt.run(course);
  });
  courseStmt.finalize();

  // Insert sample lessons
  const lessons = [
    [1, 'Introduction to Web Security', 'This lesson covers the basics of web security...', 1],
    [1, 'Common Vulnerabilities', 'Learn about the OWASP Top 10 vulnerabilities...', 2],
    [1, 'Security Best Practices', 'Best practices for secure coding...', 3],
    [2, 'SQL Injection Basics', 'Understanding SQL injection fundamentals...', 1],
    [2, 'Advanced SQL Injection', 'Advanced techniques and bypass methods...', 2],
    [2, 'SQL Injection Prevention', 'How to prevent SQL injection attacks...', 3],
    [3, 'Authentication Mechanisms', 'Different authentication methods...', 1],
    [3, 'Session Management', 'Secure session management techniques...', 2],
    [3, 'OAuth Security', 'Securing OAuth implementations...', 3]
  ];

  const lessonStmt = db.prepare('INSERT OR IGNORE INTO lessons (course_id, title, content, order_num) VALUES (?, ?, ?, ?)');
  lessons.forEach(lesson => {
    lessonStmt.run(lesson);
  });
  lessonStmt.finalize();

  // Insert sample assignments
  const assignments = [
    [1, 'Security Assessment', 'Perform a security assessment on a sample application', '2024-12-31 23:59:59'],
    [1, 'Vulnerability Report', 'Write a report on common vulnerabilities found', '2024-12-31 23:59:59'],
    [2, 'SQL Injection Lab', 'Complete the SQL injection practical exercises', '2024-12-31 23:59:59'],
    [3, 'Authentication Review', 'Review and assess an authentication system', '2024-12-31 23:59:59']
  ];

  const assignmentStmt = db.prepare('INSERT OR IGNORE INTO assignments (course_id, title, description, due_date) VALUES (?, ?, ?, ?)');
  assignments.forEach(assignment => {
    assignmentStmt.run(assignment);
  });
  assignmentStmt.finalize();

  // Insert sample user progress
  const progress = [
    [2, 1, 1], // student1 completed lesson 1
    [2, 2, 1], // student1 completed lesson 2
    [2, 4, 1], // student1 completed lesson 4
    [3, 1, 1], // student2 completed lesson 1
    [3, 2, 0]  // student2 started lesson 2 but not completed
  ];

  const progressStmt = db.prepare('INSERT OR IGNORE INTO user_progress (user_id, lesson_id, completed) VALUES (?, ?, ?)');
  progress.forEach(item => {
    progressStmt.run(item);
  });
  progressStmt.finalize();

  // Insert sample certificates
  const certificates = [
    [2, 1, 'CERT-001-2024'],
    [3, 1, 'CERT-002-2024']
  ];

  const certStmt = db.prepare('INSERT OR IGNORE INTO certificates (user_id, course_id, certificate_code) VALUES (?, ?, ?)');
  certificates.forEach(cert => {
    certStmt.run(cert);
  });
  certStmt.finalize();

  // Insert sample enrollments
  const enrollments = [
    [2, 1], // student1 enrolled in course 1
    [2, 2], // student1 enrolled in course 2
    [3, 1], // student2 enrolled in course 1
    [3, 3]  // student2 enrolled in course 3
  ];

  const enrollmentStmt = db.prepare('INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)');
  enrollments.forEach(enrollment => {
    enrollmentStmt.run(enrollment);
  });
  enrollmentStmt.finalize();

  console.log('Database initialized with sample data');
});

db.close();