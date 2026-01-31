/**
 * Express Authentication API Example
 * 
 * A complete REST API with:
 * - User registration
 * - User login
 * - Protected routes
 * - Rate limiting
 * - Proper error handling
 * - Security best practices
 */

const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 12;

// Middleware
app.use(express.json());

// In-memory user storage (use a real database in production!)
const users = [];
const sessions = new Map(); // Simple session storage

/**
 * Rate limiter for login attempts
 * Prevents brute-force attacks
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: {
    error: 'Too many login attempts, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for registration
 */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration requests per hour
  message: {
    error: 'Too many accounts created from this IP, please try again after an hour'
  }
});

/**
 * Middleware to validate email format
 */
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Middleware to validate password strength
 */
function validatePassword(password) {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special char
  const minLength = password.length >= 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return {
    isValid: minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar,
    errors: {
      minLength: !minLength ? 'Password must be at least 8 characters' : null,
      hasUpperCase: !hasUpperCase ? 'Password must contain an uppercase letter' : null,
      hasLowerCase: !hasLowerCase ? 'Password must contain a lowercase letter' : null,
      hasNumbers: !hasNumbers ? 'Password must contain a number' : null,
      hasSpecialChar: !hasSpecialChar ? 'Password must contain a special character' : null,
    }
  };
}

/**
 * Generate a simple session token
 */
function generateSessionToken() {
  return require('crypto').randomBytes(32).toString('hex');
}

/**
 * Middleware to authenticate requests
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  const session = sessions.get(token);
  
  if (!session) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
  
  req.user = session;
  next();
}

/**
 * POST /api/register
 * Register a new user
 */
app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body;
    
    // Validation
    if (!email || !password || !username) {
      return res.status(400).json({ 
        error: 'Email, username, and password are required' 
      });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).json({ 
        error: 'Invalid email format' 
      });
    }
    
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      const errors = Object.values(passwordValidation.errors).filter(e => e !== null);
      return res.status(400).json({ 
        error: 'Password does not meet requirements',
        details: errors
      });
    }
    
    // Check if user already exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ 
        error: 'User already exists' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    // Create user
    const newUser = {
      id: users.length + 1,
      email,
      username,
      passwordHash: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    
    // Return success (never return the password hash!)
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        createdAt: newUser.createdAt
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * POST /api/login
 * Login a user
 */
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }
    
    // Find user
    const user = users.find(u => u.email === email);
    
    // Use constant-time check to prevent timing attacks
    // Always hash even if user doesn't exist
    if (!user) {
      // Perform a dummy bcrypt operation to prevent timing attacks
      await bcrypt.hash(password, SALT_ROUNDS);
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    
    if (!isMatch) {
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }
    
    // Generate session token
    const token = generateSessionToken();
    sessions.set(token, {
      userId: user.id,
      email: user.email,
      username: user.username,
      loginAt: new Date().toISOString()
    });
    
    // Return success with token
    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * POST /api/logout
 * Logout a user
 */
app.post('/api/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader.split(' ')[1];
  
  sessions.delete(token);
  
  res.status(200).json({ 
    message: 'Logout successful' 
  });
});

/**
 * GET /api/profile
 * Get user profile (protected route)
 */
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ 
      error: 'User not found' 
    });
  }
  
  res.status(200).json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      createdAt: user.createdAt
    }
  });
});

/**
 * GET /api/health
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    totalUsers: users.length,
    activeSessions: sessions.size
  });
});

/**
 * Error handling middleware
 */
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error' 
  });
});

/**
 * Start server
 */
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log('\n📝 Available endpoints:');
    console.log('POST   /api/register  - Register a new user');
    console.log('POST   /api/login     - Login');
    console.log('POST   /api/logout    - Logout (requires auth)');
    console.log('GET    /api/profile   - Get profile (requires auth)');
    console.log('GET    /api/health    - Health check');
    console.log('\n💡 Test with curl or Postman:');
    console.log(`
# Register a user
curl -X POST http://localhost:${PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{"email":"alice@example.com","username":"alice","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:${PORT}/api/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"alice@example.com","password":"SecurePass123!"}'

# Get profile (replace TOKEN with your actual token)
curl -X GET http://localhost:${PORT}/api/profile \\
  -H "Authorization: Bearer TOKEN"
    `);
  });
}

module.exports = app;
