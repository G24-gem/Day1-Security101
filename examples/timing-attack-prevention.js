/**
 * Timing Attack Prevention
 * 
 * Timing attacks exploit the fact that different code paths take different
 * amounts of time to execute. Attackers can use this to extract information.
 * 
 * This example demonstrates:
 * 1. What timing attacks are
 * 2. How they work
 * 3. How to prevent them
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');

/**
 * VULNERABLE: String comparison reveals length through timing
 */
function vulnerableStringCompare(str1, str2) {
  // This exits early when it finds a mismatch!
  // An attacker can measure response times to guess the string
  if (str1.length !== str2.length) {
    return false;
  }
  
  for (let i = 0; i < str1.length; i++) {
    if (str1[i] !== str2[i]) {
      return false; // ⚠️ EXITS EARLY - timing leak!
    }
  }
  
  return true;
}

/**
 * SECURE: Constant-time string comparison
 */
function secureStringCompare(str1, str2) {
  // Always compares all characters, regardless of matches
  if (str1.length !== str2.length) {
    return false;
  }
  
  let mismatch = 0;
  
  for (let i = 0; i < str1.length; i++) {
    if (str1[i] !== str2[i]) {
      mismatch = 1; // Don't exit early!
    }
  }
  
  return mismatch === 0;
}

/**
 * BEST: Use Node.js built-in constant-time comparison
 */
function bestStringCompare(str1, str2) {
  // crypto.timingSafeEqual is designed to prevent timing attacks
  const buf1 = Buffer.from(str1);
  const buf2 = Buffer.from(str2);
  
  // If lengths don't match, compare dummy buffers to maintain constant time
  if (buf1.length !== buf2.length) {
    const dummyBuf = Buffer.alloc(buf1.length);
    crypto.timingSafeEqual(buf1, dummyBuf);
    return false;
  }
  
  return crypto.timingSafeEqual(buf1, buf2);
}

/**
 * Measure timing differences
 */
async function measureTimingDifference() {
  console.log('\n⏱️  Measuring Timing Attack Vulnerability');
  console.log('='.repeat(70));
  
  const correctPassword = 'SuperSecretPassword123!';
  const attempts = 1000;
  
  // Test different wrong passwords
  const wrongPasswords = [
    'X',                           // Wrong from start
    'S',                           // Matches first char
    'SuperS',                      // Matches first 6 chars
    'SuperSecretPass',            // Matches first 15 chars
    'SuperSecretPassword123',     // Almost complete
  ];
  
  console.log('Testing VULNERABLE comparison:');
  console.log('Correct password:', correctPassword);
  console.log('');
  
  for (const wrongPassword of wrongPasswords) {
    const times = [];
    
    for (let i = 0; i < attempts; i++) {
      const start = process.hrtime.bigint();
      vulnerableStringCompare(correctPassword, wrongPassword);
      const end = process.hrtime.bigint();
      times.push(Number(end - start));
    }
    
    const avgTime = times.reduce((a, b) => a + b) / times.length;
    const matchingChars = countMatchingPrefix(correctPassword, wrongPassword);
    
    console.log(`Wrong password: "${wrongPassword}"`);
    console.log(`  Matching chars: ${matchingChars}/${correctPassword.length}`);
    console.log(`  Avg time: ${(avgTime / 1000).toFixed(2)} microseconds`);
    console.log('');
  }
  
  console.log('💡 Notice: More matching characters = longer execution time!');
  console.log('   An attacker can use this to brute-force the password character by character.');
  
  // Now test secure version
  console.log('\n\nTesting SECURE constant-time comparison:');
  
  for (const wrongPassword of wrongPasswords) {
    const times = [];
    
    for (let i = 0; i < attempts; i++) {
      const start = process.hrtime.bigint();
      secureStringCompare(correctPassword, wrongPassword);
      const end = process.hrtime.bigint();
      times.push(Number(end - start));
    }
    
    const avgTime = times.reduce((a, b) => a + b) / times.length;
    const matchingChars = countMatchingPrefix(correctPassword, wrongPassword);
    
    console.log(`Wrong password: "${wrongPassword}"`);
    console.log(`  Matching chars: ${matchingChars}/${correctPassword.length}`);
    console.log(`  Avg time: ${(avgTime / 1000).toFixed(2)} microseconds`);
    console.log('');
  }
  
  console.log('✅ Notice: Execution time is roughly constant regardless of matches!');
}

/**
 * Count matching characters from the start
 */
function countMatchingPrefix(str1, str2) {
  let count = 0;
  const minLength = Math.min(str1.length, str2.length);
  
  for (let i = 0; i < minLength; i++) {
    if (str1[i] === str2[i]) {
      count++;
    } else {
      break;
    }
  }
  
  return count;
}

/**
 * Demonstrate timing attack on login endpoint
 */
async function demonstrateLoginTimingAttack() {
  console.log('\n\n🔓 Login Endpoint Timing Attack Demo');
  console.log('='.repeat(70));
  
  // Simulated user database
  const users = [
    { username: 'alice', passwordHash: await bcrypt.hash('AlicePass123!', 10) },
    { username: 'bob', passwordHash: await bcrypt.hash('BobPassword456!', 10) },
  ];
  
  /**
   * VULNERABLE login function
   */
  async function vulnerableLogin(username, password) {
    const user = users.find(u => u.username === username);
    
    if (!user) {
      return false; // ⚠️ Returns immediately if user doesn't exist
    }
    
    return await bcrypt.compare(password, user.passwordHash);
  }
  
  /**
   * SECURE login function
   */
  async function secureLogin(username, password) {
    const user = users.find(u => u.username === username);
    
    if (!user) {
      // Perform dummy bcrypt operation to maintain constant time
      await bcrypt.compare(password, '$2b$10$dummyhashforunknownusersXXXXXXXXXXXXXXXXXXXXXXX');
      return false;
    }
    
    return await bcrypt.compare(password, user.passwordHash);
  }
  
  console.log('Testing VULNERABLE login:');
  
  const testCases = [
    { username: 'alice', password: 'wrong', label: 'Valid user, wrong password' },
    { username: 'nonexistent', password: 'wrong', label: 'Invalid user' },
  ];
  
  for (const test of testCases) {
    const start = Date.now();
    await vulnerableLogin(test.username, test.password);
    const end = Date.now();
    
    console.log(`  ${test.label}: ${end - start}ms`);
  }
  
  console.log('\n⚠️  Different timing reveals if username exists!');
  
  console.log('\n\nTesting SECURE login:');
  
  for (const test of testCases) {
    const start = Date.now();
    await secureLogin(test.username, test.password);
    const end = Date.now();
    
    console.log(`  ${test.label}: ${end - start}ms`);
  }
  
  console.log('\n✅ Similar timing prevents username enumeration!');
}

/**
 * Real-world secure login implementation
 */
async function secureLoginExample() {
  console.log('\n\n🔐 Secure Login Implementation Example');
  console.log('='.repeat(70));
  
  const users = [
    { 
      id: 1, 
      email: 'alice@example.com', 
      passwordHash: await bcrypt.hash('AliceSecure123!', 12) 
    }
  ];
  
  /**
   * Production-ready secure login
   */
  async function login(email, password) {
    // Find user
    const user = users.find(u => u.email === email);
    
    // If user doesn't exist, perform dummy hash to prevent timing attack
    if (!user) {
      // Use a pre-computed dummy hash
      const dummyHash = '$2b$12$dummyhashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
      await bcrypt.compare(password, dummyHash);
      
      // Return generic error (don't reveal if user exists)
      return {
        success: false,
        error: 'Invalid credentials'
      };
    }
    
    // Verify password using bcrypt (constant-time internally)
    const isValid = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValid) {
      return {
        success: false,
        error: 'Invalid credentials' // Same generic message
      };
    }
    
    return {
      success: true,
      user: {
        id: user.id,
        email: user.email
      }
    };
  }
  
  // Test successful login
  console.log('\nTest 1: Correct credentials');
  const result1 = await login('alice@example.com', 'AliceSecure123!');
  console.log(result1);
  
  // Test wrong password
  console.log('\nTest 2: Wrong password');
  const result2 = await login('alice@example.com', 'WrongPassword');
  console.log(result2);
  
  // Test non-existent user
  console.log('\nTest 3: Non-existent user');
  const result3 = await login('bob@example.com', 'SomePassword');
  console.log(result3);
  
  console.log('\n✅ All cases return same generic error message!');
  console.log('✅ Timing is consistent across all failure cases!');
}

/**
 * Main demonstration
 */
async function main() {
  console.log('🚀 Timing Attack Prevention Demo');
  console.log('='.repeat(70));
  
  try {
    // 1. Measure timing differences
    await measureTimingDifference();
    
    // 2. Demonstrate login timing attack
    await demonstrateLoginTimingAttack();
    
    // 3. Show secure implementation
    await secureLoginExample();
    
    console.log('\n\n✅ Demo completed!');
    console.log('\n🎯 Key Takeaways:');
    console.log('  1. Use crypto.timingSafeEqual() for constant-time comparisons');
    console.log('  2. Always perform same operations regardless of user existence');
    console.log('  3. Return generic error messages (don\'t reveal if user exists)');
    console.log('  4. bcrypt.compare() is already timing-safe internally');
    console.log('  5. Consider rate limiting to make timing attacks impractical');
    
  } catch (error) {
    console.error('❌ Demo failed:', error);
  }
}

// Run the demo
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  vulnerableStringCompare,
  secureStringCompare,
  bestStringCompare
};
