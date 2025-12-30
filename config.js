// Configuration file for secure version
module.exports = {
  // Security is always enforced
  SECURE_MODE: true,  // Secure mode
  
  // Other configuration options
  PORT: process.env.PORT || 5001,  // Different port to avoid conflicts
  SESSION_SECRET: process.env.SESSION_SECRET || 'secure-secret-key'
};
