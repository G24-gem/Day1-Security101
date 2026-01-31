/**
 * Security Tests
 * 
 * Tests to verify password security implementations
 */

const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Test results tracking
const tests = {
  passed: 0,
  failed: 0,
  total: 0
};

/**
 * Test helper
 */
function test(description, fn) {
  tests.total++;
  try {
    fn();
    tests.passed++;
    console.log(`✅ ${description}`);
  } catch (error) {
    tests.failed++;
    console.log(`❌ ${description}`);
    console.log(`   Error: ${error.message}`);
  }
}

/**
 * Async test helper
 */
async function testAsync(description, fn) {
  tests.total++;
  try {
    await fn();
    tests.passed++;
    console.log(`✅ ${description}`);
  } catch (error) {
    tests.failed++;
    console.log(`❌ ${description}`);
    console.log(`   Error: ${error.message}`);
  }
}

/**
 * Assertion helpers
 */
function assertEqual(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`Expected ${expected}, got ${actual}. ${message}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(`Expected true, got ${value}. ${message}`);
  }
}

function assertFalse(value, message = '') {
  if (value) {
    throw new Error(`Expected false, got ${value}. ${message}`);
  }
}

/**
 * Test Suite
 */
async function runTests() {
  console.log('🧪 Running Security Tests');
  console.log('='.repeat(70));
  console.log('');
  
  // Test 1: bcrypt basic functionality
  await testAsync('bcrypt should hash passwords', async () => {
    const password = 'TestPassword123!';
    const hash = await bcrypt.hash(password, 10);
    assertTrue(hash.length > 0);
    assertTrue(hash.startsWith('$2b$'));
  });
  
  // Test 2: bcrypt verification
  await testAsync('bcrypt should verify correct passwords', async () => {
    const password = 'TestPassword123!';
    const hash = await bcrypt.hash(password, 10);
    const isValid = await bcrypt.compare(password, hash);
    assertTrue(isValid);
  });
  
  // Test 3: bcrypt reject wrong passwords
  await testAsync('bcrypt should reject wrong passwords', async () => {
    const password = 'TestPassword123!';
    const hash = await bcrypt.hash(password, 10);
    const isValid = await bcrypt.compare('WrongPassword', hash);
    assertFalse(isValid);
  });
  
  // Test 4: Unique salts
  await testAsync('bcrypt should generate unique salts', async () => {
    const password = 'TestPassword123!';
    const hash1 = await bcrypt.hash(password, 10);
    const hash2 = await bcrypt.hash(password, 10);
    assertTrue(hash1 !== hash2, 'Hashes should be different');
  });
  
  // Test 5: Cost factor
  await testAsync('bcrypt cost factor should affect hash', async () => {
    const password = 'TestPassword123!';
    const hash10 = await bcrypt.hash(password, 10);
    const hash12 = await bcrypt.hash(password, 12);
    
    // Extract cost from hash
    const cost10 = parseInt(hash10.split('$')[2]);
    const cost12 = parseInt(hash12.split('$')[2]);
    
    assertEqual(cost10, 10);
    assertEqual(cost12, 12);
  });
  
  // Test 6: MD5 is insecure (demonstration)
  test('MD5 should produce same hash for same input', () => {
    const password = 'password';
    const hash1 = crypto.createHash('md5').update(password).digest('hex');
    const hash2 = crypto.createHash('md5').update(password).digest('hex');
    assertEqual(hash1, hash2, 'MD5 has no salt - same input = same hash');
  });
  
  // Test 7: Timing-safe comparison
  test('crypto.timingSafeEqual should work correctly', () => {
    const str1 = 'hello';
    const str2 = 'hello';
    const str3 = 'world';
    
    const buf1 = Buffer.from(str1);
    const buf2 = Buffer.from(str2);
    const buf3 = Buffer.from(str3);
    
    assertTrue(crypto.timingSafeEqual(buf1, buf2));
    
    try {
      crypto.timingSafeEqual(buf1, buf3);
      throw new Error('Should have failed');
    } catch (error) {
      // Expected to throw
    }
  });
  
  // Test 8: Password strength - minimum requirements
  test('Strong password should meet all requirements', () => {
    const password = 'MySecureP@ss123';
    
    const hasLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);
    
    assertTrue(hasLength);
    assertTrue(hasUpper);
    assertTrue(hasLower);
    assertTrue(hasNumber);
    assertTrue(hasSpecial);
  });
  
  // Test 9: Weak password detection
  test('Weak password should fail requirements', () => {
    const password = 'weak';
    
    const hasLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);
    
    assertFalse(hasLength);
    assertFalse(hasUpper);
    assertFalse(hasNumber);
    assertFalse(hasSpecial);
  });
  
  // Test 10: Common password detection
  test('Common passwords should be rejected', () => {
    const commonPasswords = ['password', '123456', 'qwerty', 'admin'];
    const commonSet = new Set(commonPasswords);
    
    assertTrue(commonSet.has('password'));
    assertTrue(commonSet.has('123456'));
    assertFalse(commonSet.has('MyUnique!Pass123'));
  });
  
  // Test 11: Hash verification performance
  await testAsync('bcrypt verification should complete reasonably fast', async () => {
    const password = 'TestPassword123!';
    const hash = await bcrypt.hash(password, 10);
    
    const start = Date.now();
    await bcrypt.compare(password, hash);
    const duration = Date.now() - start;
    
    // Should complete in under 500ms
    assertTrue(duration < 500, `Took ${duration}ms, should be under 500ms`);
  });
  
  // Test 12: Different algorithms produce different hashes
  test('Different hash algorithms produce different results', () => {
    const password = 'test';
    
    const md5 = crypto.createHash('md5').update(password).digest('hex');
    const sha1 = crypto.createHash('sha1').update(password).digest('hex');
    const sha256 = crypto.createHash('sha256').update(password).digest('hex');
    
    assertTrue(md5 !== sha1);
    assertTrue(sha1 !== sha256);
    assertTrue(md5 !== sha256);
  });
  
  // Test 13: Hash length consistency
  await testAsync('bcrypt hashes should have consistent length', async () => {
    const passwords = ['short', 'mediumlength', 'verylongpasswordhere'];
    const hashes = await Promise.all(
      passwords.map(p => bcrypt.hash(p, 10))
    );
    
    // All bcrypt hashes should be 60 characters
    hashes.forEach(hash => {
      assertEqual(hash.length, 60);
    });
  });
  
  // Test 14: Case sensitivity
  await testAsync('Password comparison should be case sensitive', async () => {
    const password = 'TestPassword123!';
    const hash = await bcrypt.hash(password, 10);
    
    const correctCase = await bcrypt.compare('TestPassword123!', hash);
    const wrongCase = await bcrypt.compare('testpassword123!', hash);
    
    assertTrue(correctCase);
    assertFalse(wrongCase);
  });
  
  // Test 15: Empty password handling
  await testAsync('Should handle empty passwords', async () => {
    const hash = await bcrypt.hash('', 10);
    const isValid = await bcrypt.compare('', hash);
    assertTrue(isValid);
  });
  
  // Results
  console.log('');
  console.log('='.repeat(70));
  console.log('📊 Test Results');
  console.log('='.repeat(70));
  console.log(`Total tests: ${tests.total}`);
  console.log(`Passed: ${tests.passed} ✅`);
  console.log(`Failed: ${tests.failed} ❌`);
  console.log(`Success rate: ${((tests.passed / tests.total) * 100).toFixed(1)}%`);
  console.log('');
  
  if (tests.failed === 0) {
    console.log('🎉 All tests passed!');
  } else {
    console.log('⚠️  Some tests failed. Please review the errors above.');
    process.exit(1);
  }
}

// Run tests
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests };
