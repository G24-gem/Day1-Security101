# Quick Start Guide - Password Security

## 🚀 Getting Started in 5 Minutes

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Run Your First Example

```bash
# Basic bcrypt demonstration
npm run example:basic
```

You'll see:
- How bcrypt hashes passwords
- How unique salts work
- Login/registration flow
- Performance metrics

### Step 3: Try the Express API

```bash
# Start the authentication API server
npm run example:api
```

Then in another terminal, test it:

```bash
# Register a user
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Use the token from login response to access protected routes
curl -X GET http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Step 4: Check Password Strength

```bash
npm run example:strength
```

This shows you:
- How to validate password strength
- Password entropy calculation
- Time to crack estimates
- Generated strong passwords

### Step 5: Learn About Advanced Topics

```bash
# See Argon2 (most secure algorithm)
npm run example:argon2

# Learn about timing attack prevention
npm run example:timing

# Understand password migration strategies
npm run example:migration
```

### Step 6: Run Tests

```bash
npm test
```

## 📖 What to Learn Next

### Beginner Path
1. Start with `basic-bcrypt.js` - understand the fundamentals
2. Move to `password-strength.js` - learn validation
3. Build with `express-auth-api.js` - create a real API

### Advanced Path
1. Study `timing-attack-prevention.js` - security details
2. Explore `argon2-example.js` - modern algorithms
3. Review `migration-example.js` - production scenarios

## 🎯 Key Takeaways

### ✅ DO:
```javascript
const bcrypt = require('bcrypt');

// Hash password with 12 rounds
const hash = await bcrypt.hash(password, 12);

// Verify password
const isValid = await bcrypt.compare(password, hash);
```

### ❌ DON'T:
```javascript
// NEVER do this!
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
```

## 💡 Common Questions

**Q: Which algorithm should I use?**
A: For new projects, use Argon2id. For existing projects, bcrypt is fine.

**Q: How many rounds for bcrypt?**
A: 12 rounds is recommended. Increase as hardware improves.

**Q: Can I use SHA-256 for passwords?**
A: No! It's too fast. Use bcrypt, scrypt, or Argon2.

**Q: How do I migrate from MD5?**
A: Use the lazy migration strategy in `migration-example.js`.

## 🔗 Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [bcrypt npm docs](https://www.npmjs.com/package/bcrypt)
- [Argon2 npm docs](https://www.npmjs.com/package/argon2)

## 🐛 Troubleshooting

### bcrypt installation fails
```bash
# On Linux/Mac
npm install bcrypt --build-from-source

# On Windows
npm install --global windows-build-tools
npm install bcrypt
```

### Argon2 installation fails
```bash
# Install build dependencies first
# Ubuntu/Debian:
sudo apt-get install build-essential

# Then install argon2
npm install argon2
```

## 📚 Next Steps

After mastering password security, move on to:
- Day 2: API Design
- Day 3: Error Handling
- Day 4: CORS Configuration

Happy learning! 🚀
