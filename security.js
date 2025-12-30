const config = require('./config');
const sqlite3 = require('sqlite3').verbose();

// Function to sanitize user input to prevent SQL injection and XSS
function sanitizeInput(input) {
  if (typeof input === 'string') {
    // Remove or escape dangerous characters
    return input.replace(/'/g, "''").replace(/;/g, '');
  }
  return input;
}

// Function to sanitize HTML content to prevent XSS
function sanitizeHTML(html) {
  if (typeof html !== 'string') {
    return html;
  }
  
  // Remove dangerous HTML tags and attributes
  return html
    .replace(/<script[^>]*>.*?<\/script>/gi, '') // Remove script tags
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '') // Remove iframe tags
    .replace(/<object[^>]*>.*?<\/object>/gi, '') // Remove object tags
    .replace(/<embed[^>]*>.*?<\/embed>/gi, '') // Remove embed tags
    .replace(/<form[^>]*>.*?<\/form>/gi, '') // Remove form tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .replace(/<\/?[a-z][a-z0-9]*[^<>]*>/gi, function(tag) {
      // Allow only safe tags
      if (tag.match(/<(\/)?(p|br|strong|em|u|i|b|div|span|ul|ol|li|h[1-6]|blockquote|code|pre)>/i)) {
        return tag;
      }
      return '';
    });
}

// Function to validate user access to resources (for IDOR protection)
function validateUserAccess(req, userId) {
  // Always check if the requested user ID matches the current user's ID
  // or if the user is an admin, regardless of config mode
  try {
    return req.session && req.session.user && (req.session.user.id == userId || req.session.user.role === 'admin');
  } catch (error) {
    console.error('Error in validateUserAccess:', error);
    return false;
  }
}

// Function to validate course access (for IDOR protection)
function validateCourseAccess(req, courseId, db, callback) {
  // Always check if the user is enrolled in the course or is an admin, regardless of config mode
  try {
    if (!req.session || !req.session.user) {
      return callback(false);
    }
    
    const query = `SELECT c.id FROM courses c LEFT JOIN enrollments e ON c.id = e.course_id WHERE c.id = ? AND (e.user_id = ? OR c.instructor_id = ? OR ? = 'admin')`;
    
    db.get(query, [courseId, req.session.user.id, req.session.user.id, req.session.user.role], (err, result) => {
      if (err) {
        console.error('Course access validation error:', err);
        return callback(false);
      }
      callback(!!result);
    });
  } catch (error) {
    console.error('Error in validateCourseAccess:', error);
    callback(false);
  }
}

// Function to validate profile update (for mass assignment protection)
function validateProfileUpdate(req, updates) {
  // Always only allow updating specific fields, regardless of config mode
  const allowedFields = ['username', 'email', 'password', 'created_at'];
  const filteredUpdates = {};
  
  for (const field in updates) {
    if (allowedFields.includes(field)) {
      filteredUpdates[field] = updates[field];
    }
  }
  
  return filteredUpdates;
}

// Function to validate admin access
function isAdmin(req) {
  // Always only allow access if user is actually an admin, regardless of config mode
  return req.session.user && req.session.user.role === 'admin';
}

// Function to prevent insecure deserialization
function safeParse(jsonString) {
  // Always use a safe parsing method that prevents prototype pollution, regardless of config mode
  try {
    // More comprehensive validation to prevent prototype pollution
    if (jsonString.includes('__proto__') || jsonString.includes('constructor') || jsonString.includes('prototype')) {
      throw new Error('Invalid input');
    }
    
    // Parse the JSON
    const parsed = JSON.parse(jsonString);
    
    // Additional validation to prevent prototype pollution by checking the parsed object
    if (parsed && typeof parsed === 'object') {
      // Check for dangerous properties in the parsed object
      for (const key in parsed) {
        if (key === '__proto__' || key === 'constructor') {
          throw new Error('Invalid input');
        }
      }
    }
    
    return parsed;
  } catch (e) {
    throw e;
  }
}

module.exports = {
  sanitizeInput,
  sanitizeHTML,
  validateUserAccess,
  validateCourseAccess,
  validateProfileUpdate,
  isAdmin,
  safeParse
};