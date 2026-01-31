/**
 * Day 1: Password Security with scrypt
 * 
 * This example demonstrates:
 * - How to hash passwords with scrypt (Node.js built-in crypto)
 * - Understanding scrypt parameters (N, r, p)
 * - Memory-hard properties for security
 * - Real-world usage without external dependencies
 */

const crypto = require('crypto');
const { promisify } = require('util');

// Promisify scrypt for async/await usage
const scryptAsync = promisify(crypto.scrypt);

console.log('🔒 DAY 1: PASSWORD SECURITY WITH SCRYPT\n');
console.log('='.repeat(50));

/**
 * scrypt Configuration
 * 
 * scrypt parameters:
 * - N: CPU/memory cost parameter (must be power of 2)
 * - r: Block size parameter
 * - p: Parallelization parameter
 * - keylen: Length of the derived key
 */

const CONFIG = {
    // N: CPU/Memory cost (2^14 = 16384)
    // Higher = exponentially more secure but slower
    N: 16384, // 2^14 (recommended minimum)
    
    // r: Block size (affects memory usage)
    r: 8,
    
    // p: Parallelization factor
    p: 1,
    
    // Derived key length
    keylen: 64, // 64 bytes = 512 bits
    
    // Salt length
    saltLength: 16 // 16 bytes = 128 bits
};

/**
 * Example 1: Basic Password Hashing with scrypt
 */
async function example1_BasicHashing() {
    console.log('\n📝 EXAMPLE 1: Basic Password Hashing with scrypt\n');
    
    const plainPassword = 'SuperSecret123!';
    
    console.log(`Original password: "${plainPassword}"`);
    console.log('Hashing password with scrypt...\n');
    
    // 1. Generate random salt
    const salt = crypto.randomBytes(CONFIG.saltLength);
    console.log(`Generated salt: ${salt.toString('hex')}`);
    
    // 2. Hash the password
    const derivedKey = await scryptAsync(
        plainPassword,
        salt,
        CONFIG.keylen,
        { N: CONFIG.N, r: CONFIG.r, p: CONFIG.p }
    );
    
    // 3. Combine salt and hash for storage
    const hashedPassword = `${salt.toString('hex')}:${derivedKey.toString('hex')}`;
    
    console.log(`\nHashed password: ${hashedPassword}`);
    console.log(`Total length: ${hashedPassword.length} characters`);
    
    console.log('\n🔍 Understanding the scrypt hash:');
    console.log(`   Salt (hex): ${salt.toString('hex')} (${CONFIG.saltLength} bytes)`);
    console.log(`   Hash (hex): ${derivedKey.toString('hex')} (${CONFIG.keylen} bytes)`);
    console.log(`   Format: salt:hash`);
}

/**
 * Helper function to hash passwords
 */
async function hashPassword(password) {
    const salt = crypto.randomBytes(CONFIG.saltLength);
    const derivedKey = await scryptAsync(
        password,
        salt,
        CONFIG.keylen,
        { N: CONFIG.N, r: CONFIG.r, p: CONFIG.p }
    );
    return `${salt.toString('hex')}:${derivedKey.toString('hex')}`;
}

/**
 * Helper function to verify passwords
 */
async function verifyPassword(password, hashedPassword) {
    // Split the hash to get salt and hash
    const [saltHex, hashHex] = hashedPassword.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const originalHash = Buffer.from(hashHex, 'hex');
    
    // Hash the provided password with the same salt
    const derivedKey = await scryptAsync(
        password,
        salt,
        CONFIG.keylen,
        { N: CONFIG.N, r: CONFIG.r, p: CONFIG.p }
    );
    
    // Use crypto.timingSafeEqual to prevent timing attacks
    return crypto.timingSafeEqual(originalHash, derivedKey);
}

/**
 * Example 2: Password Verification
 */
async function example2_PasswordVerification() {
    console.log('\n📝 EXAMPLE 2: Password Verification\n');
    
    const correctPassword = 'MyPassword123';
    const wrongPassword = 'WrongPassword';
    
    // Hash the correct password
    const hashedPassword = await hashPassword(correctPassword);
    console.log(`Stored hash: ${hashedPassword.substring(0, 60)}...\n`);
    
    console.log('Testing password verification...\n');
    
    // Test correct password
    const isCorrect = await verifyPassword(correctPassword, hashedPassword);
    console.log(`✅ Correct password ("${correctPassword}"): ${isCorrect}`);
    
    // Test wrong password
    const isWrong = await verifyPassword(wrongPassword, hashedPassword);
    console.log(`❌ Wrong password ("${wrongPassword}"): ${isWrong}`);
}

/**
 * Example 3: Why Salting Matters
 */
async function example3_SaltingDemonstration() {
    console.log('\n📝 EXAMPLE 3: Why Salting Matters\n');
    
    const password = 'CommonPassword123';
    
    // Hash the same password three times
    const hash1 = await hashPassword(password);
    const hash2 = await hashPassword(password);
    const hash3 = await hashPassword(password);
    
    console.log('Same password, hashed 3 times:\n');
    console.log(`Hash 1: ${hash1}`);
    console.log(`Hash 2: ${hash2}`);
    console.log(`Hash 3: ${hash3}`);
    
    console.log('\n🔍 Notice: All hashes are DIFFERENT!');
    console.log('   Each hash has a unique random salt (first part before colon)');
    console.log('   This prevents rainbow table and dictionary attacks');
}

/**
 * Example 4: Cost Parameter Impact
 */
async function example4_CostComparison() {
    console.log('\n📝 EXAMPLE 4: Cost Parameter (N) Impact\n');
    
    const password = 'TestPassword123';
    const nValues = [
        { N: 2 ** 12, desc: 'Low (N=4096)' },      // 4096
        { N: 2 ** 14, desc: 'Medium (N=16384)' },  // 16384 (recommended)
        { N: 2 ** 16, desc: 'High (N=65536)' }     // 65536
    ];
    
    console.log('Hashing with different N values:\n');
    
    for (const config of nValues) {
        const salt = crypto.randomBytes(CONFIG.saltLength);
        const startTime = Date.now();
        
        await scryptAsync(
            password,
            salt,
            CONFIG.keylen,
            { N: config.N, r: CONFIG.r, p: CONFIG.p }
        );
        
        const duration = Date.now() - startTime;
        console.log(`${config.desc.padEnd(25)} | Time: ${duration.toString().padStart(4)}ms`);
    }
    
    console.log('\n💡 Key Takeaway:');
    console.log('   N parameter: Higher = More secure but exponentially slower');
    console.log('   Recommended: N=2^14 (16384) for most web applications');
    console.log('   Each doubling of N roughly doubles the time and memory required');
}

/**
 * Example 5: Timing-Safe Password Comparison
 */
async function example5_TimingSafeComparison() {
    console.log('\n📝 EXAMPLE 5: Timing-Safe Password Comparison\n');
    
    const password = 'SecurePassword123!';
    const hashedPassword = await hashPassword(password);
    
    console.log('Why crypto.timingSafeEqual() is important:\n');
    
    console.log('❌ INSECURE (vulnerable to timing attacks):');
    console.log('   if (hash1 === hash2) { ... }');
    console.log('   → String comparison stops at first difference');
    console.log('   → Attacker can measure time to guess characters\n');
    
    console.log('✅ SECURE (timing-safe):');
    console.log('   crypto.timingSafeEqual(hash1, hash2)');
    console.log('   → Compares all bytes regardless of differences');
    console.log('   → Same time whether match or mismatch\n');
    
    // Demonstrate timing-safe comparison
    const [saltHex, hashHex] = hashedPassword.split(':');
    const hash = Buffer.from(hashHex, 'hex');
    
    console.log('Testing with timing-safe comparison:');
    const isMatch = crypto.timingSafeEqual(hash, hash);
    console.log(`✅ Hashes match: ${isMatch}`);
}

/**
 * Example 6: Real-World User Registration
 */
async function example6_UserRegistration() {
    console.log('\n📝 EXAMPLE 6: Real-World User Registration\n');
    
    const users = [];
    
    async function registerUser(username, email, password) {
        console.log(`\n🔐 Registering user: ${username}`);
        
        // 1. Validate password
        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }
        
        // 2. Hash password with scrypt
        console.log('   Hashing password with scrypt...');
        const hashedPassword = await hashPassword(password);
        
        // 3. Store user
        const user = {
            id: users.length + 1,
            username,
            email,
            password: hashedPassword,
            createdAt: new Date()
        };
        
        users.push(user);
        
        console.log('   ✅ User registered successfully!');
        console.log(`   User ID: ${user.id}`);
        console.log(`   Password hash: ${hashedPassword.substring(0, 50)}...`);
        
        return { id: user.id, username, email };
    }
    
    // Register users
    await registerUser('alice', 'alice@example.com', 'AliceSecure123!');
    await registerUser('bob', 'bob@example.com', 'BobPassword456!');
    
    console.log(`\n📊 Total users registered: ${users.length}`);
}

/**
 * Example 7: User Login Flow
 */
async function example7_UserLogin() {
    console.log('\n📝 EXAMPLE 7: User Login Flow\n');
    
    const users = [
        {
            id: 1,
            username: 'alice',
            email: 'alice@example.com',
            password: await hashPassword('AliceSecure123!')
        }
    ];
    
    async function loginUser(email, password) {
        console.log(`\n🔓 Login attempt for: ${email}`);
        
        // 1. Find user
        const user = users.find(u => u.email === email);
        if (!user) {
            console.log('   ❌ User not found');
            return { success: false, message: 'Invalid credentials' };
        }
        
        // 2. Verify password
        console.log('   Verifying password with scrypt...');
        const isPasswordValid = await verifyPassword(password, user.password);
        
        if (!isPasswordValid) {
            console.log('   ❌ Invalid password');
            return { success: false, message: 'Invalid credentials' };
        }
        
        console.log('   ✅ Login successful!');
        return {
            success: true,
            user: { id: user.id, username: user.username, email: user.email }
        };
    }
    
    // Test successful login
    await loginUser('alice@example.com', 'AliceSecure123!');
    
    // Test failed login
    await loginUser('alice@example.com', 'WrongPassword');
}

/**
 * Example 8: Memory-Hard Properties
 */
async function example8_MemoryHardness() {
    console.log('\n📝 EXAMPLE 8: Understanding scrypt Memory-Hardness\n');
    
    console.log('Why scrypt is memory-hard:\n');
    console.log('✅ Requires significant RAM to compute');
    console.log('   → Makes GPU/ASIC attacks expensive');
    console.log('   → Attackers need expensive hardware with lots of memory\n');
    
    console.log('Memory usage calculation:');
    console.log(`   Memory ≈ 128 × N × r bytes`);
    console.log(`   With N=${CONFIG.N}, r=${CONFIG.r}:`);
    const memoryUsage = 128 * CONFIG.N * CONFIG.r;
    console.log(`   Memory ≈ ${(memoryUsage / 1024 / 1024).toFixed(2)} MiB per hash\n`);
    
    console.log('💡 Security benefit:');
    console.log('   Attacker trying 1 billion passwords needs:');
    const totalMemory = memoryUsage * 1000000000 / 1024 / 1024 / 1024;
    console.log(`   ${totalMemory.toFixed(0)} GB of RAM if parallelized!`);
    console.log('   This makes large-scale attacks prohibitively expensive.');
}

/**
 * Example 9: Why Use scrypt? (Built-in vs External Libraries)
 */
async function example9_WhyScrypt() {
    console.log('\n📝 EXAMPLE 9: Why Use scrypt?\n');
    
    console.log('✅ Advantages of scrypt:\n');
    console.log('1. Built into Node.js (no external dependencies)');
    console.log('   → No need to install bcrypt or Argon2');
    console.log('   → Easier deployment and fewer security updates\n');
    
    console.log('2. Memory-hard algorithm');
    console.log('   → Resistant to GPU/ASIC attacks');
    console.log('   → More expensive to crack at scale\n');
    
    console.log('3. Configurable parameters');
    console.log('   → Adjust N, r, p for security/performance balance');
    console.log('   → Can increase over time as hardware improves\n');
    
    console.log('🤔 When to use each algorithm?\n');
    console.log('bcrypt:');
    console.log('   ✅ Mature, widely used, battle-tested');
    console.log('   ✅ Good for general web applications');
    console.log('   ❌ Less memory-hard (easier GPU attacks)\n');
    
    console.log('scrypt:');
    console.log('   ✅ Built into Node.js (no dependencies)');
    console.log('   ✅ Memory-hard (better GPU resistance)');
    console.log('   ✅ Good balance of security and simplicity\n');
    
    console.log('Argon2:');
    console.log('   ✅ Most secure (won PHC 2015)');
    console.log('   ✅ Best GPU/ASIC resistance');
    console.log('   ❌ Requires external library\n');
    
    console.log('Recommendation:');
    console.log('   → Use scrypt if you want built-in Node.js solution');
    console.log('   → Use Argon2 if maximum security is required');
    console.log('   → Use bcrypt if already in your stack');
}

/**
 * Run all examples
 */
async function runAllExamples() {
    try {
        await example1_BasicHashing();
        await example2_PasswordVerification();
        await example3_SaltingDemonstration();
        await example4_CostComparison();
        await example5_TimingSafeComparison();
        await example6_UserRegistration();
        await example7_UserLogin();
        await example8_MemoryHardness();
        await example9_WhyScrypt();
        
        console.log('\n' + '='.repeat(50));
        console.log('✅ All examples completed successfully!');
        console.log('='.repeat(50));
        
    } catch (error) {
        console.error('\n❌ Error running examples:', error.message);
    }
}

// Run if this file is executed directly
if (require.main === module) {
    runAllExamples();
}

module.exports = {
    hashPassword,
    verifyPassword,
    example1_BasicHashing,
    example2_PasswordVerification,
    example3_SaltingDemonstration,
    example4_CostComparison,
    example5_TimingSafeComparison,
    example6_UserRegistration,
    example7_UserLogin,
    example8_MemoryHardness,
    example9_WhyScrypt
};
