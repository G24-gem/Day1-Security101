# Day 1: 🔒 Password Security - Hashing & Salting

## 📚 Table of Contents
- [Why Password Security Matters](#why-password-security-matters)
- [The LinkedIn 2012 Hack - What Went Wrong](#the-linkedin-2012-hack---what-went-wrong)
- [Understanding Hashing vs Encryption](#understanding-hashing-vs-encryption)
- [What is Salting?](#what-is-salting)
- [Choosing the Right Algorithm](#choosing-the-right-algorithm)
- [Real-World Implementation](#real-world-implementation)
- [Security Best Practices](#security-best-practices)
- [Common Mistakes to Avoid](#common-mistakes-to-avoid)

---

## Why Password Security Matters

Every year, millions of user credentials are compromised due to poor password storage practices. When attackers gain access to a database, the **ONLY** thing protecting your users is how you've stored their passwords.

### The Cost of Getting It Wrong:
- **Yahoo (2013-2014)**: 3 billion accounts compromised
- **LinkedIn (2012)**: 6.5 million passwords leaked
- **Adobe (2013)**: 153 million user records exposed

---

## The LinkedIn 2012 Hack - What Went Wrong

In 2012, LinkedIn suffered a massive breach where 6.5 million password hashes were stolen and published online. The problem?

❌ **What LinkedIn Did Wrong:**
- Used unsalted SHA-1 hashes
- No individual salt per password
- SHA-1 is fast (bad for passwords!)
- Easy to crack with rainbow tables

✅ **What They Should Have Done:**
- Use bcrypt/scrypt/Argon2
- Unique salt per password
- Slow hashing algorithm
- Proper security audits

---

## Understanding Hashing vs Encryption

### 🔐 Encryption (Reversible)
```
Password → [Encrypt with Key] → Ciphertext
Ciphertext → [Decrypt with Key] → Password
```
**Use case:** Protecting data you need to retrieve later

### 🔒 Hashing (One-Way)
```
Password → [Hash Function] → Hash
Hash → [???] → Password (IMPOSSIBLE!)
```
**Use case:** Storing passwords (you NEVER need the original)

### Why Hash, Not Encrypt?
If encryption keys are compromised, ALL passwords are exposed. Hashes can't be reversed!

---

## What is Salting?

A **salt** is a random string added to each password before hashing.

### Without Salt:
```
User1: "password123" → hash("password123") → abc123def...
User2: "password123" → hash("password123") → abc123def...
```
☠️ Same password = Same hash = Vulnerable to rainbow tables!

### With Salt:
```
User1: "password123" + "randomSalt1" → hash → xyz789...
User2: "password123" + "randomSalt2" → hash → mno456...
```
✅ Same password = Different hashes = Rainbow tables useless!

---

## Choosing the Right Algorithm

| Algorithm | Speed | Security | Recommendation |
|-----------|-------|----------|----------------|
| MD5 | ⚡ Very Fast | ❌ Broken | NEVER USE |
| SHA-1 | ⚡ Very Fast | ❌ Broken | NEVER USE |
| SHA-256 | ⚡ Fast | ⚠️ Too Fast | Not for passwords |
| bcrypt | 🐌 Slow | ✅ Good | ✅ Recommended |
| scrypt | 🐌 Slower | ✅ Better | ✅ Recommended |
| Argon2 | 🐌 Configurable | ✅ Best | ✅ Highly Recommended |

### Why "Slow" is Good for Passwords

**Fast Hashing = Bad for Passwords**
- Attackers can try billions of passwords per second
- Modern GPUs can crack SHA-256 at 100+ billion hashes/second

**Slow Hashing = Good for Passwords**
- bcrypt: ~1,000 hashes/second
- Makes brute-force attacks impractical
- Legitimate users don't notice the tiny delay

---

## Real-World Implementation

See the `examples/` directory for complete implementations:

1. **`basic-bcrypt.js`** - Simple user registration & login
2. **`express-auth-api.js`** - Full REST API with authentication
3. **`password-strength.js`** - Password validation & strength checking
4. **`migration-example.js`** - Migrating from weak to strong hashing
5. **`argon2-example.js`** - Using Argon2 (most secure)
6. **`timing-attack-prevention.js`** - Preventing timing attacks

---

## Security Best Practices

### ✅ DO:
- Use bcrypt, scrypt, or Argon2
- Use a unique salt per password (automatic with bcrypt/Argon2)
- Set appropriate work factors (cost)
- Use HTTPS to protect passwords in transit
- Implement rate limiting on login endpoints
- Use constant-time comparison for hash checking

### ❌ DON'T:
- Use MD5, SHA-1, or plain SHA-256 for passwords
- Store passwords in plain text (EVER!)
- Use the same salt for all passwords
- Log passwords (even hashed ones)
- Return specific error messages ("Wrong password" vs "User not found")
- Allow unlimited login attempts

---

## Common Mistakes to Avoid

### Mistake #1: Using Fast Hash Functions
```javascript
// ❌ WRONG - SHA-256 is too fast!
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update(password).digest('hex');
```

```javascript
// ✅ CORRECT - bcrypt is designed for passwords
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
```

### Mistake #2: Not Using Enough Salt Rounds
```javascript
// ❌ TOO WEAK - Only 4 rounds
const hash = await bcrypt.hash(password, 4);
```

```javascript
// ✅ SECURE - 12+ rounds recommended
const hash = await bcrypt.hash(password, 12);
```

### Mistake #3: Timing Attacks
```javascript
// ❌ VULNERABLE - Different timing reveals info
if (userInputHash === storedHash) {
  return true;
}
```

```javascript
// ✅ SECURE - Constant time comparison
const crypto = require('crypto');
const match = crypto.timingSafeEqual(
  Buffer.from(userInputHash),
  Buffer.from(storedHash)
);
```

---

## 📦 Installation & Setup

```bash
# Clone the repository
git clone <your-repo-url>

# Navigate to Day 1
cd day1-password-security

# Install dependencies
npm install

# Run examples
node examples/basic-bcrypt.js
node examples/express-auth-api.js
```

---

## 🧪 Running Tests

```bash
npm test
```

---

## 📚 Further Reading

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [bcrypt npm package](https://www.npmjs.com/package/bcrypt)
- [Argon2 - Password Hashing Competition Winner](https://github.com/P-H-C/phc-winner-argon2)
- [How To Safely Store A Password](https://codahale.com/how-to-safely-store-a-password/)

---

## 🤝 Contributing

Found a security issue or want to improve the examples? PRs welcome!

---

## 📝 License

MIT License - Feel free to use in your projects!

---

**Next**: [Day 2 - API Design →](../day2-api-design)
