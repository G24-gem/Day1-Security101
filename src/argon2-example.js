/**
 * Day 1: Password Security with Argon2
 * 
 * This example demonstrates:
 * - How to hash passwords with Argon2
 * - Different Argon2 variants (Argon2i, Argon2d, Argon2id)
 * - Memory and time cost parameters
 * - Why Argon2 won the Password Hashing Competition 2015
 */

const argon2 = require('argon2');

console.log('🔒 DAY 1: PASSWORD SECURITY WITH ARGON2\n');
console.log('='.repeat(50));

/**
 * Argon2 Configuration
 * 
 * Argon2 has three variants:
 * - Argon2d: Faster, maximizes resistance to GPU attacks (used for cryptocurrencies)
 * - Argon2i: Slower, maximizes resistance to side-channel attacks (used for password hashing)
 * - Argon2id: Hybrid of Argon2i and Argon2d (RECOMMENDED for password hashing)
 */

const CONFIG = {
    // Type of Argon2 to use
    type: argon2.argon2id, // RECOMMENDED
    
    // Memory cost: Amount of memory used (in KiB)
    // Higher = more secure but uses more RAM
    memoryCost: 2 ** 16, // 64 MiB (65536 KiB)
    
    // Time cost: Number of iterations
    // Higher = more secure but slower
    timeCost: 3, // 3 iterations
    
    // Parallelism: Number of threads
    // Should match number of CPU cores available
    parallelism: 1
};

/**
 * Example 1: Basic Password Hashing with Argon2
 */
async function example1_BasicHashing() {
    console.log('\n📝 EXAMPLE 1: Basic Password Hashing with Argon2\n');
    
    const plainPassword = 'SuperSecret123!';
    
    console.log(`Original password: "${plainPassword}"`);
    console.log('Hashing password with Argon2id...\n');
    
    // Hash the password
    const hashedPassword = await argon2.hash(plainPassword, CONFIG);
    
    console.log(`Hashed password: ${hashedPassword}`);
    console.log(`Length: ${hashedPassword.length} characters`);
    
    // Hash format:
    // $argon2id$v=19$m=65536,t=3,p=1$base64salt$base64hash
    console.log('\n🔍 Understanding the Argon2 hash:');
    console.log('   Format: $argon2id$v=19$m=65536,t=3,p=1$salt$hash');
    console.log('   - argon2id: Algorithm variant (hybrid mode)');
    console.log('   - v=19: Version number');
    console.log('   - m=65536: Memory cost in KiB (64 MiB)');
    console.log('   - t=3: Time cost (iterations)');
    console.log('   - p=1: Parallelism (threads)');
    console.log('   - salt: Random salt (base64 encoded)');
    console.log('   - hash: Actual hash (base64 encoded)');
}

/**
 * Example 2: Password Verification
 */
async function example2_PasswordVerification() {
    console.log('\n📝 EXAMPLE 2: Password Verification\n');
    
    const correctPassword = 'MyPassword123';
    const wrongPassword = 'WrongPassword';
    
    // Hash the correct password
    const hashedPassword = await argon2.hash(correctPassword, CONFIG);
    
    console.log('Testing password verification...\n');
    
    // Test correct password
    const isCorrect = await argon2.verify(hashedPassword, correctPassword);
    console.log(`✅ Correct password ("${correctPassword}"): ${isCorrect}`);
    
    // Test wrong password
    const isWrong = await argon2.verify(hashedPassword, wrongPassword);
    console.log(`❌ Wrong password ("${wrongPassword}"): ${isWrong}`);
}

/**
 * Example 3: Comparing Argon2 Variants
 */
async function example3_Argon2Variants() {
    console.log('\n📝 EXAMPLE 3: Comparing Argon2 Variants\n');
    
    const password = 'TestPassword123';
    
    // Argon2i (optimized for password hashing, resistant to side-channel attacks)
    const hashArgon2i = await argon2.hash(password, {
        ...CONFIG,
        type: argon2.argon2i
    });
    
    // Argon2d (optimized for cryptocurrencies, faster)
    const hashArgon2d = await argon2.hash(password, {
        ...CONFIG,
        type: argon2.argon2d
    });
    
    // Argon2id (hybrid, RECOMMENDED)
    const hashArgon2id = await argon2.hash(password, {
        ...CONFIG,
        type: argon2.argon2id
    });
    
    console.log('Same password, different Argon2 variants:\n');
    console.log(`Argon2i:  ${hashArgon2i}`);
    console.log(`Argon2d:  ${hashArgon2d}`);
    console.log(`Argon2id: ${hashArgon2id}`);
    
    console.log('\n💡 Which to use?');
    console.log('   ✅ Argon2id: RECOMMENDED for password hashing (best of both worlds)');
    console.log('   ⚠️  Argon2i: Use if side-channel attacks are a major concern');
    console.log('   ⚠️  Argon2d: Use for cryptocurrencies, NOT for passwords');
}

/**
 * Example 4: Memory and Time Cost Comparison
 */
async function example4_CostComparison() {
    console.log('\n📝 EXAMPLE 4: Memory and Time Cost Impact\n');
    
    const password = 'BenchmarkPassword123';
    
    const configs = [
        { memoryCost: 2 ** 14, timeCost: 2, desc: 'Low (16 MiB, 2 iterations)' },
        { memoryCost: 2 ** 16, timeCost: 3, desc: 'Medium (64 MiB, 3 iterations)' },
        { memoryCost: 2 ** 18, timeCost: 4, desc: 'High (256 MiB, 4 iterations)' }
    ];
    
    console.log('Hashing with different cost parameters:\n');
    
    for (const config of configs) {
        const startTime = Date.now();
        
        await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: config.memoryCost,
            timeCost: config.timeCost,
            parallelism: 1
        });
        
        const duration = Date.now() - startTime;
        
        console.log(`${config.desc.padEnd(35)} | Time: ${duration.toString().padStart(4)}ms`);
    }
    
    console.log('\n💡 Key Takeaway:');
    console.log('   Higher memory + time cost = More secure but slower');
    console.log('   Recommended: 64 MiB memory, 3-4 iterations for web apps');
    console.log('   Adjust based on your server resources and security needs');
}

/**
 * Example 5: Real-World User Registration with Argon2
 */
async function example5_UserRegistration() {
    console.log('\n📝 EXAMPLE 5: Real-World User Registration\n');
    
    const users = [];
    
    /**
     * Register a new user with Argon2 password hashing
     */
    async function registerUser(username, email, password) {
        console.log(`\n🔐 Registering user: ${username}`);
        
        // 1. Validate password
        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }
        
        // 2. Hash password with Argon2id
        console.log('   Hashing password with Argon2id...');
        const hashedPassword = await argon2.hash(password, CONFIG);
        
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
 * Example 6: User Login with Argon2 Verification
 */
async function example6_UserLogin() {
    console.log('\n📝 EXAMPLE 6: User Login with Argon2\n');
    
    const users = [
        {
            id: 1,
            username: 'alice',
            email: 'alice@example.com',
            password: await argon2.hash('AliceSecure123!', CONFIG)
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
        
        // 2. Verify password with Argon2
        console.log('   Verifying password with Argon2...');
        const isPasswordValid = await argon2.verify(user.password, password);
        
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
 * Example 7: Checking if Hash Needs Rehashing
 */
async function example7_HashRehashing() {
    console.log('\n📝 EXAMPLE 7: Checking if Hash Needs Rehashing\n');
    
    // Old hash with lower security parameters
    const oldPassword = 'UserPassword123';
    const oldHash = await argon2.hash(oldPassword, {
        type: argon2.argon2id,
        memoryCost: 2 ** 12, // Only 4 MiB (too low!)
        timeCost: 2,
        parallelism: 1
    });
    
    console.log('Old hash (weak parameters):');
    console.log(`   ${oldHash}\n`);
    
    // Check if hash needs rehashing (due to updated security parameters)
    const needsRehash = await argon2.needsRehash(oldHash, CONFIG);
    
    console.log(`Needs rehashing with current config? ${needsRehash}`);
    
    if (needsRehash) {
        console.log('\n🔄 Rehashing password with updated parameters...');
        const newHash = await argon2.hash(oldPassword, CONFIG);
        console.log(`   New hash: ${newHash.substring(0, 50)}...`);
        console.log('   ✅ Hash updated with stronger parameters!');
    }
    
    console.log('\n💡 Best Practice:');
    console.log('   Check needsRehash() during login');
    console.log('   Upgrade hashes when security parameters improve');
    console.log('   This keeps old users secure without forcing password resets');
}

/**
 * Example 8: Why Argon2 is Better Than bcrypt
 */
async function example8_Argon2VsBcrypt() {
    console.log('\n📝 EXAMPLE 8: Why Argon2 Won Password Hashing Competition\n');
    
    console.log('Argon2 advantages over bcrypt:\n');
    console.log('✅ Memory-hard algorithm (resistant to GPU/ASIC attacks)');
    console.log('   - bcrypt: ~4 KiB memory');
    console.log('   - Argon2: Configurable (typically 64+ MiB)');
    console.log('   - Attackers need expensive hardware with lots of RAM\n');
    
    console.log('✅ Configurable parameters');
    console.log('   - Memory cost');
    console.log('   - Time cost');
    console.log('   - Parallelism\n');
    
    console.log('✅ Three variants for different use cases');
    console.log('   - Argon2i: Side-channel attack resistant');
    console.log('   - Argon2d: Faster, GPU attack resistant');
    console.log('   - Argon2id: Best of both (RECOMMENDED)\n');
    
    console.log('✅ Modern and actively maintained');
    console.log('   - Won Password Hashing Competition (2015)');
    console.log('   - Recommended by OWASP\n');
    
    console.log('🤔 When to use bcrypt instead?');
    console.log('   - Legacy systems already using bcrypt');
    console.log('   - Extremely low-memory environments');
    console.log('   - Otherwise, prefer Argon2id for new projects!');
}

/**
 * Run all examples
 */
async function runAllExamples() {
    try {
        await example1_BasicHashing();
        await example2_PasswordVerification();
        await example3_Argon2Variants();
        await example4_CostComparison();
        await example5_UserRegistration();
        await example6_UserLogin();
        await example7_HashRehashing();
        await example8_Argon2VsBcrypt();
        
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
    example1_BasicHashing,
    example2_PasswordVerification,
    example3_Argon2Variants,
    example4_CostComparison,
    example5_UserRegistration,
    example6_UserLogin,
    example7_HashRehashing,
    example8_Argon2VsBcrypt
};
