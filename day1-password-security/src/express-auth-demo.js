/**
 * Day 1: Complete Express Authentication Demo
 * 
 * This example demonstrates:
 * - Full user authentication system with Express.js
 * - Registration and login endpoints
 * - Rate limiting to prevent brute-force attacks
 * - Account lockout after failed attempts
 * - Password validation
 * - Security headers with Helmet
 * - Environment variables for configuration
 */

const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(helmet()); // Security headers

console.log('🔒 EXPRESS AUTHENTICATION DEMO\n');
console.log('='.repeat(50));

// Configuration
const CONFIG = {
    PORT: process.env.PORT || 3000,
    SALT_ROUNDS: parseInt(process.env.SALT_ROUNDS) || 10,
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutes in milliseconds
};

// In-memory "database" (use real database in production!)
const users = [];
const loginAttempts = new Map(); // Track failed login attempts

/**
 * Rate limiter for authentication endpoints
 * Prevents brute-force attacks by limiting requests
 */
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many authentication attempts. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * Password validation function
 */
function validatePassword(password) {
    const errors = [];
    
    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return errors;
}

/**
 * Email validation
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Check if account is locked
 */
function isAccountLocked(email) {
    const attempts = loginAttempts.get(email);
    
    if (!attempts) {
        return false;
    }
    
    if (attempts.count >= CONFIG.MAX_LOGIN_ATTEMPTS) {
        const lockoutEnd = attempts.lastAttempt + CONFIG.LOCKOUT_TIME;
        const now = Date.now();
        
        if (now < lockoutEnd) {
            const minutesLeft = Math.ceil((lockoutEnd - now) / 60000);
            return { locked: true, minutesLeft };
        } else {
            // Lockout period expired, reset attempts
            loginAttempts.delete(email);
            return false;
        }
    }
    
    return false;
}

/**
 * Record failed login attempt
 */
function recordFailedAttempt(email) {
    const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: 0 };
    attempts.count++;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(email, attempts);
}

/**
 * Clear login attempts on successful login
 */
function clearLoginAttempts(email) {
    loginAttempts.delete(email);
}

/**
 * GET /
 * Welcome endpoint
 */
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to the Authentication API',
        endpoints: {
            'POST /register': 'Register a new user',
            'POST /login': 'Login with email and password',
            'GET /users': 'List all registered users (demo only)',
        },
    });
});

/**
 * POST /register
 * Register a new user
 */
app.post('/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({
                error: 'Username, email, and password are required',
            });
        }
        
        // Validate email format
        if (!validateEmail(email)) {
            return res.status(400).json({
                error: 'Invalid email format',
            });
        }
        
        // Validate password strength
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({
                error: 'Password does not meet requirements',
                details: passwordErrors,
            });
        }
        
        // Check if user already exists
        if (users.find(u => u.email === email)) {
            return res.status(409).json({
                error: 'User with this email already exists',
            });
        }
        
        if (users.find(u => u.username === username)) {
            return res.status(409).json({
                error: 'Username already taken',
            });
        }
        
        // Hash password
        console.log(`\n🔐 Registering new user: ${username}`);
        const hashedPassword = await bcrypt.hash(password, CONFIG.SALT_ROUNDS);
        
        // Create user
        const user = {
            id: users.length + 1,
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
        };
        
        users.push(user);
        
        console.log(`✅ User registered successfully: ${email}`);
        
        // Return user without password
        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
            },
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /login
 * Authenticate user
 */
app.post('/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                error: 'Email and password are required',
            });
        }
        
        // Check if account is locked
        const lockStatus = isAccountLocked(email);
        if (lockStatus && lockStatus.locked) {
            return res.status(429).json({
                error: `Account temporarily locked. Try again in ${lockStatus.minutesLeft} minutes.`,
                lockedUntil: lockStatus.minutesLeft,
            });
        }
        
        // Find user
        const user = users.find(u => u.email === email);
        
        if (!user) {
            // Don't reveal if user exists or not (security best practice)
            recordFailedAttempt(email);
            return res.status(401).json({
                error: 'Invalid credentials',
            });
        }
        
        // Verify password
        console.log(`\n🔓 Login attempt for: ${email}`);
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            console.log(`❌ Invalid password for: ${email}`);
            recordFailedAttempt(email);
            
            const attempts = loginAttempts.get(email);
            const remainingAttempts = CONFIG.MAX_LOGIN_ATTEMPTS - attempts.count;
            
            return res.status(401).json({
                error: 'Invalid credentials',
                remainingAttempts: remainingAttempts > 0 ? remainingAttempts : 0,
            });
        }
        
        // Successful login
        console.log(`✅ Login successful for: ${email}`);
        clearLoginAttempts(email);
        
        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
            },
            // In production, you would return a JWT token here
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...(demo token)',
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * GET /users
 * List all users (for demo purposes only!)
 * NEVER expose this in production!
 */
app.get('/users', (req, res) => {
    // Return users without passwords
    const safeUsers = users.map(({ password, ...user }) => user);
    res.json({
        count: safeUsers.length,
        users: safeUsers,
    });
});

/**
 * Error handling middleware
 */
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Something went wrong',
    });
});

/**
 * Start server
 */
function startServer() {
    app.listen(CONFIG.PORT, () => {
        console.log('\n' + '='.repeat(50));
        console.log(`✅ Server running on http://localhost:${CONFIG.PORT}`);
        console.log('='.repeat(50));
        console.log('\n📝 API Endpoints:');
        console.log(`   POST http://localhost:${CONFIG.PORT}/register`);
        console.log(`   POST http://localhost:${CONFIG.PORT}/login`);
        console.log(`   GET  http://localhost:${CONFIG.PORT}/users`);
        console.log('\n💡 Example requests:');
        console.log('\nRegister:');
        console.log(`curl -X POST http://localhost:${CONFIG.PORT}/register \\`);
        console.log(`  -H "Content-Type: application/json" \\`);
        console.log(`  -d '{"username":"alice","email":"alice@example.com","password":"SecurePass123!"}'`);
        console.log('\nLogin:');
        console.log(`curl -X POST http://localhost:${CONFIG.PORT}/login \\`);
        console.log(`  -H "Content-Type: application/json" \\`);
        console.log(`  -d '{"email":"alice@example.com","password":"SecurePass123!"}'`);
        console.log('\n' + '='.repeat(50));
    });
}

// Run server if this file is executed directly
if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };
