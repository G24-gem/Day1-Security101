/**
 * Day 1: Password Security with bcrypt
 * 
 * This example demonstrates:
 * - How to hash passwords with bcrypt
 * - How to verify passwords
 * - Understanding salt rounds (work factor)
 * - Real-world user registration and login flow
 */

const bcrypt = require('bcrypt');

// CONFIGURATION
const SALT_ROUNDS = 10; // Higher = more secure but slower
// 10 rounds ≈ 65ms
// 12 rounds ≈ 260ms
// 15 rounds ≈ 2000ms

console.log('🔒 DAY 1: PASSWORD SECURITY WITH BCRYPT\n');
console.log('='.repeat(50));

/**
 * Example 1: Basic Password Hashing
 */
async function example1_BasicHashing() {
    console.log('\n📝 EXAMPLE 1: Basic Password Hashing\n');
    
    const plainPassword = 'SuperSecret123!';
    
    console.log(`Original password: "${plainPassword}"`);
    console.log('Hashing password...\n');
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(plainPassword, SALT_ROUNDS);
    
    console.log(`Hashed password: ${hashedPassword}`);
    console.log(`Length: ${hashedPassword.length} characters`);
    
    // Hash format breakdown:
    // $2b$10$N9qo8uLOickgx2ZMRZoMye/IY9jbj6I1Hw9p0ZHiLYEyD/uJzH9v6
    // ├─┤ ├┤ ├────────────────────┤ ├──────────────────────────┤
    // │   │  │                     │
    // │   │  Salt (22 chars)      Hash (31 chars)
    // │   Cost factor (10)
    // Algorithm identifier ($2b = bcrypt)
    
    console.log('\n🔍 Understanding the hash:');
    console.log(`   Algorithm: $2b (bcrypt)`);
    console.log(`   Cost factor: ${SALT_ROUNDS} rounds`);
    console.log(`   Salt: ${hashedPassword.substring(7, 29)} (automatically generated)`);
    console.log(`   Hash: ${hashedPassword.substring(29)}`);
}

/**
 * Example 2: Password Verification
 */
async function example2_PasswordVerification() {
    console.log('\n📝 EXAMPLE 2: Password Verification\n');
    
    const correctPassword = 'MyPassword123';
    const wrongPassword = 'WrongPassword';
    
    // Hash the correct password
    const hashedPassword = await bcrypt.hash(correctPassword, SALT_ROUNDS);
    
    console.log('Testing password verification...\n');
    
    // Test correct password
    const isCorrect = await bcrypt.compare(correctPassword, hashedPassword);
    console.log(`✅ Correct password ("${correctPassword}"): ${isCorrect}`);
    
    // Test wrong password
    const isWrong = await bcrypt.compare(wrongPassword, hashedPassword);
    console.log(`❌ Wrong password ("${wrongPassword}"): ${isWrong}`);
}

/**
 * Example 3: Why Salting Matters - Same Password, Different Hashes
 */
async function example3_SaltingDemonstration() {
    console.log('\n📝 EXAMPLE 3: Why Salting Matters\n');
    
    const password = 'CommonPassword123';
    
    // Hash the same password three times
    const hash1 = await bcrypt.hash(password, SALT_ROUNDS);
    const hash2 = await bcrypt.hash(password, SALT_ROUNDS);
    const hash3 = await bcrypt.hash(password, SALT_ROUNDS);
    
    console.log('Same password, hashed 3 times:\n');
    console.log(`Hash 1: ${hash1}`);
    console.log(`Hash 2: ${hash2}`);
    console.log(`Hash 3: ${hash3}`);
    
    console.log('\n🔍 Notice: All hashes are DIFFERENT!');
    console.log('   This is because each hash uses a unique random salt.');
    console.log('   This prevents rainbow table attacks.');
}

/**
 * Example 4: Cost Factor Impact on Security and Performance
 */
async function example4_CostFactorComparison() {
    console.log('\n📝 EXAMPLE 4: Cost Factor (Salt Rounds) Impact\n');
    
    const password = 'TestPassword123';
    const rounds = [8, 10, 12];
    
    console.log('Hashing the same password with different cost factors:\n');
    
    for (const round of rounds) {
        const startTime = Date.now();
        const hash = await bcrypt.hash(password, round);
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        console.log(`Rounds: ${round.toString().padStart(2)} | Time: ${duration.toString().padStart(4)}ms | Hash: ${hash.substring(0, 40)}...`);
    }
    
    console.log('\n💡 Key Takeaway:');
    console.log('   Higher rounds = More secure but slower');
    console.log('   Recommended: 10-12 rounds for most applications');
    console.log('   Adjust based on your security needs and performance requirements');
}

/**
 * Example 5: Real-World User Registration Flow
 */
async function example5_UserRegistration() {
    console.log('\n📝 EXAMPLE 5: Real-World User Registration\n');
    
    // Simulated user database
    const users = [];
    
    /**
     * Register a new user
     */
    async function registerUser(username, email, password) {
        console.log(`\n🔐 Registering user: ${username}`);
        
        // 1. Validate password strength (in real app, use a library like validator)
        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }
        
        // 2. Hash the password
        console.log('   Hashing password...');
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        // 3. Store user in database (simulated)
        const user = {
            id: users.length + 1,
            username,
            email,
            password: hashedPassword, // NEVER store plaintext!
            createdAt: new Date()
        };
        
        users.push(user);
        
        console.log('   ✅ User registered successfully!');
        console.log(`   User ID: ${user.id}`);
        console.log(`   Password hash stored: ${hashedPassword.substring(0, 40)}...`);
        
        return { id: user.id, username, email }; // Don't return password!
    }
    
    // Register some users
    await registerUser('alice', 'alice@example.com', 'AliceSecure123!');
    await registerUser('bob', 'bob@example.com', 'BobPassword456!');
    
    console.log(`\n📊 Total users registered: ${users.length}`);
}

/**
 * Example 6: Real-World User Login Flow
 */
async function example6_UserLogin() {
    console.log('\n📝 EXAMPLE 6: Real-World User Login\n');
    
    // Simulated user database
    const users = [
        {
            id: 1,
            username: 'alice',
            email: 'alice@example.com',
            password: await bcrypt.hash('AliceSecure123!', SALT_ROUNDS)
        }
    ];
    
    /**
     * Authenticate a user
     */
    async function loginUser(email, password) {
        console.log(`\n🔓 Login attempt for: ${email}`);
        
        // 1. Find user by email
        const user = users.find(u => u.email === email);
        
        if (!user) {
            console.log('   ❌ User not found');
            return { success: false, message: 'Invalid credentials' };
        }
        
        // 2. Compare password with stored hash
        console.log('   Verifying password...');
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
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
    
    // Test failed login (wrong password)
    await loginUser('alice@example.com', 'WrongPassword');
    
    // Test failed login (user not found)
    await loginUser('nonexistent@example.com', 'AnyPassword');
}

/**
 * Example 7: Password Update Flow
 */
async function example7_PasswordUpdate() {
    console.log('\n📝 EXAMPLE 7: Password Update Flow\n');
    
    let user = {
        id: 1,
        username: 'alice',
        password: await bcrypt.hash('OldPassword123!', SALT_ROUNDS)
    };
    
    /**
     * Update user password
     */
    async function updatePassword(userId, currentPassword, newPassword) {
        console.log(`\n🔄 Updating password for user ID: ${userId}`);
        
        // 1. Verify current password
        console.log('   Verifying current password...');
        const isCurrentValid = await bcrypt.compare(currentPassword, user.password);
        
        if (!isCurrentValid) {
            console.log('   ❌ Current password is incorrect');
            return { success: false, message: 'Current password is incorrect' };
        }
        
        // 2. Validate new password
        if (newPassword.length < 8) {
            console.log('   ❌ New password too short');
            return { success: false, message: 'New password must be at least 8 characters' };
        }
        
        // 3. Check if new password is same as old
        const isSameAsOld = await bcrypt.compare(newPassword, user.password);
        if (isSameAsOld) {
            console.log('   ❌ New password cannot be the same as old password');
            return { success: false, message: 'New password must be different' };
        }
        
        // 4. Hash new password
        console.log('   Hashing new password...');
        const newHashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        
        // 5. Update password in database
        user.password = newHashedPassword;
        
        console.log('   ✅ Password updated successfully!');
        return { success: true, message: 'Password updated' };
    }
    
    // Test password update
    await updatePassword(1, 'OldPassword123!', 'NewSecurePassword456!');
    
    // Verify new password works
    const isNewPasswordValid = await bcrypt.compare('NewSecurePassword456!', user.password);
    console.log(`\n✅ Verification: New password works: ${isNewPasswordValid}`);
}

/**
 * Run all examples
 */
async function runAllExamples() {
    try {
        await example1_BasicHashing();
        await example2_PasswordVerification();
        await example3_SaltingDemonstration();
        await example4_CostFactorComparison();
        await example5_UserRegistration();
        await example6_UserLogin();
        await example7_PasswordUpdate();
        
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
    example3_SaltingDemonstration,
    example4_CostFactorComparison,
    example5_UserRegistration,
    example6_UserLogin,
    example7_PasswordUpdate
};
