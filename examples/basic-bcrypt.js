/**
 * Basic bcrypt Example - User Registration & Login
 * 
 * This example demonstrates:
 * 1. How to hash passwords during registration
 * 2. How to verify passwords during login
 * 3. Why bcrypt is better than simple hashing
 */

const bcrypt = require('bcrypt');

// Configuration
const SALT_ROUNDS = 12; // Higher = more secure but slower (10-12 recommended)

/**
 * Simulated user database (in real apps, use PostgreSQL, MongoDB, etc.)
 */
const users = [];

/**
 * Register a new user
 * @param {string} username 
 * @param {string} password - Plain text password (never store this!)
 */
async function registerUser(username, password) {
  console.log(`\n🔐 Registering user: ${username}`);
  console.log(`Original password: ${password}`);
  
  // Check if user already exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    throw new Error('User already exists!');
  }
  
  try {
    // Generate salt and hash password
    // bcrypt automatically generates a unique salt for each password
    const startTime = Date.now();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const endTime = Date.now();
    
    console.log(`Hashed password: ${hashedPassword}`);
    console.log(`Hashing took: ${endTime - startTime}ms`);
    console.log(`Salt rounds: ${SALT_ROUNDS}`);
    
    // Store user with hashed password
    const newUser = {
      id: users.length + 1,
      username,
      passwordHash: hashedPassword,
      createdAt: new Date()
    };
    
    users.push(newUser);
    console.log(`✅ User registered successfully!`);
    
    return { id: newUser.id, username: newUser.username };
  } catch (error) {
    console.error('❌ Registration failed:', error.message);
    throw error;
  }
}

/**
 * Login a user
 * @param {string} username 
 * @param {string} password - Plain text password to verify
 */
async function loginUser(username, password) {
  console.log(`\n🔓 Login attempt for: ${username}`);
  
  try {
    // Find user in database
    const user = users.find(u => u.username === username);
    
    if (!user) {
      // Security note: Don't reveal whether username exists
      // Use same generic message for both cases
      throw new Error('Invalid credentials');
    }
    
    // Compare provided password with stored hash
    const startTime = Date.now();
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    const endTime = Date.now();
    
    console.log(`Password verification took: ${endTime - startTime}ms`);
    
    if (!isMatch) {
      console.log('❌ Invalid password');
      throw new Error('Invalid credentials');
    }
    
    console.log('✅ Login successful!');
    return { id: user.id, username: user.username };
  } catch (error) {
    console.error('❌ Login failed:', error.message);
    throw error;
  }
}

/**
 * Demonstrate why the same password produces different hashes
 */
async function demonstrateSaltUniqueness() {
  console.log('\n📊 Demonstrating Salt Uniqueness');
  console.log('=' .repeat(60));
  
  const password = 'MySecretPassword123!';
  
  // Hash the same password multiple times
  const hash1 = await bcrypt.hash(password, SALT_ROUNDS);
  const hash2 = await bcrypt.hash(password, SALT_ROUNDS);
  const hash3 = await bcrypt.hash(password, SALT_ROUNDS);
  
  console.log(`Original password: ${password}`);
  console.log(`\nHash #1: ${hash1}`);
  console.log(`Hash #2: ${hash2}`);
  console.log(`Hash #3: ${hash3}`);
  console.log(`\n💡 Notice: Same password, different hashes!`);
  console.log(`This is because bcrypt generates a unique salt each time.`);
  
  // But they all verify correctly!
  const match1 = await bcrypt.compare(password, hash1);
  const match2 = await bcrypt.compare(password, hash2);
  const match3 = await bcrypt.compare(password, hash3);
  
  console.log(`\n✅ All hashes verify correctly: ${match1 && match2 && match3}`);
}

/**
 * Demonstrate the cost of different salt rounds
 */
async function demonstrateCostFactor() {
  console.log('\n⏱️  Demonstrating Cost Factor Impact');
  console.log('=' .repeat(60));
  
  const password = 'TestPassword123!';
  const rounds = [4, 8, 10, 12, 14];
  
  for (const round of rounds) {
    const startTime = Date.now();
    await bcrypt.hash(password, round);
    const endTime = Date.now();
    
    console.log(`Rounds: ${round.toString().padStart(2)} | Time: ${(endTime - startTime).toString().padStart(4)}ms`);
  }
  
  console.log(`\n💡 Notice: Each increase in rounds roughly doubles the time!`);
  console.log(`This makes brute-force attacks exponentially harder.`);
}

/**
 * Main demonstration
 */
async function main() {
  console.log('🚀 bcrypt Password Security Demo');
  console.log('=' .repeat(60));
  
  try {
    // 1. Show salt uniqueness
    await demonstrateSaltUniqueness();
    
    // 2. Show cost factor impact
    await demonstrateCostFactor();
    
    // 3. Register some users
    console.log('\n👥 User Registration');
    console.log('=' .repeat(60));
    
    await registerUser('alice', 'AliceSecurePass123!');
    await registerUser('bob', 'BobPassword456!');
    await registerUser('charlie', 'Charlie789Strong!');
    
    // Try to register duplicate
    try {
      await registerUser('alice', 'DifferentPassword');
    } catch (error) {
      console.log(`\n⚠️  Expected error: ${error.message}`);
    }
    
    // 4. Test login scenarios
    console.log('\n\n🔐 Login Attempts');
    console.log('=' .repeat(60));
    
    // Successful login
    await loginUser('alice', 'AliceSecurePass123!');
    
    // Wrong password
    try {
      await loginUser('bob', 'WrongPassword');
    } catch (error) {
      console.log(`⚠️  Expected error: ${error.message}`);
    }
    
    // Non-existent user
    try {
      await loginUser('dave', 'SomePassword');
    } catch (error) {
      console.log(`⚠️  Expected error: ${error.message}`);
    }
    
    // Display all users (without passwords!)
    console.log('\n\n📋 Registered Users');
    console.log('=' .repeat(60));
    users.forEach(user => {
      console.log(`ID: ${user.id} | Username: ${user.username} | Created: ${user.createdAt.toISOString()}`);
      console.log(`Hash: ${user.passwordHash.substring(0, 40)}...`);
    });
    
    console.log('\n\n✅ Demo completed successfully!');
    
  } catch (error) {
    console.error('❌ Demo failed:', error);
  }
}

// Run the demo
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { registerUser, loginUser };
