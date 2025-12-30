const fs = require('fs');
const path = require('path');

// Function to update the security mode in config file
function updateSecurityMode(secureMode) {
  return new Promise((resolve, reject) => {
    const configPath = path.join(__dirname, 'config.js');
    
    fs.readFile(configPath, 'utf8', (err, data) => {
      if (err) {
        reject(err);
        return;
      }
      
      // Update the SECURE_MODE setting
      let updatedData;
      if (secureMode) {
        updatedData = data.replace(
          /SECURE_MODE: process\.env\.SECURE_MODE === 'true' \|\| false/,
          "SECURE_MODE: process.env.SECURE_MODE === 'true' || true  // Secure mode enabled"
        );
        // Also handle the case where it's already in secure mode
        updatedData = updatedData.replace(
          /SECURE_MODE: process\.env\.SECURE_MODE === 'true' \|\| true  \/\/ Secure mode enabled/,
          "SECURE_MODE: process.env.SECURE_MODE === 'true' || true  // Secure mode enabled"
        );
      } else {
        updatedData = data.replace(
          /SECURE_MODE: process\.env\.SECURE_MODE === 'true' \|\| true  \/\/ Secure mode enabled/,
          "SECURE_MODE: process.env.SECURE_MODE === 'true' || false"
        );
        // Also handle the case where it's already in vulnerable mode
        updatedData = updatedData.replace(
          /SECURE_MODE: process\.env\.SECURE_MODE === 'true' \|\| false/,
          "SECURE_MODE: process.env.SECURE_MODE === 'true' || false"
        );
      }
      
      fs.writeFile(configPath, updatedData, 'utf8', (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  });
}

module.exports = {
  updateSecurityMode
};