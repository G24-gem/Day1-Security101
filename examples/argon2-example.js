/**
 * Argon2 Example - The Most Secure Password Hashing Algorithm
 * 
 * Argon2 won the Password Hashing Competition (PHC) in 2015
 * and is recommended by OWASP as the first choice for hashing passwords.
 * 
 * Advantages over bcrypt:
 * - Resistant to GPU/ASIC attacks
 * - Configurable memory usage (protects against hardware attacks)
 * - Three variants: Argon2d, Argon2i, Argon2id
 * - More modern and actively maintained
 */

const argon2 = require('argon2');

/**
 * Argon2 Configuration Options
 */
const ARGON2_OPTIONS = {
  type: argon2.argon2id, // Argon2id is recommended (hybrid of Argon2i and Argon2d)
  memoryCost: 2 ** 16,   // 64 MB (amount of memory to use)
  timeCost: 3,           // Number of iterations
  parallelism: 1,        // Number of threads
};

// Simulated user database
const users = [];

/**
 * Register a user with Argon2
 */
async function registerUser(username, password) {
  console.log(`\n🔐 Registering user with Argon2: ${username}`);
  
  try {
    // Check if user exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      throw new Error('User already exists');
    }
    
    // Hash password with Argon2
    const startTime = Date.now();
    const hashedPassword = await argon2.hash(password, ARGON2_OPTIONS);
    const endTime = Date.now();
    
    console.log(`Password: ${password}`);
    console.log(`Hash: ${hashedPassword}`);
    console.log(`Hashing time: ${endTime - startTime}ms`);
    console.log(`Memory cost: ${ARGON2_OPTIONS.memoryCost / 1024} KB`);
    console.log(`Time cost: ${ARGON2_OPTIONS.timeCost} iterations`);
    
    // Store user
    const newUser = {
      id: users.length + 1,
      username,
      passwordHash: hashedPassword,
      createdAt: new Date(),
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
 * Login a user with Argon2
 */
async function loginUser(username, password) {
  console.log(`\n🔓 Login attempt: ${username}`);
  
  try {
    // Find user
    const user = users.find(u => u.username === username);
    
    if (!user) {
      throw new Error('Invalid credentials');
    }
    
    // Verify password
    const startTime = Date.now();
    const isMatch = await argon2.verify(user.passwordHash, password);
    const endTime = Date.now();
    
    console.log(`Verification time: ${endTime - startTime}ms`);
    
    if (!isMatch) {
      console.log('❌ Invalid password');
      throw new Error('Invalid credentials');
    }
    
    // Check if hash needs rehashing (parameters changed)
    const needsRehash = await argon2.needsRehash(user.passwordHash, ARGON2_OPTIONS);
    
    if (needsRehash) {
      console.log('⚠️  Hash parameters outdated, rehashing...');
      const newHash = await argon2.hash(password, ARGON2_OPTIONS);
      user.passwordHash = newHash;
      console.log('✅ Password rehashed with updated parameters');
    }
    
    console.log('✅ Login successful!');
    return { id: user.id, username: user.username };
  } catch (error) {
    console.error('❌ Login failed:', error.message);
    throw error;
  }
}

/**
 * Compare Argon2 variants
 */
async function compareArgon2Variants() {
  console.log('\n📊 Comparing Argon2 Variants');
  console.log('=' .repeat(70));
  
  const password = 'TestPassword123!';
  const variants = [
    { name: 'Argon2d', type: argon2.argon2d, description: 'Faster, resistant to time-memory tradeoff attacks' },
    { name: 'Argon2i', type: argon2.argon2i, description: 'Resistant to side-channel attacks' },
    { name: 'Argon2id', type: argon2.argon2id, description: 'Hybrid - RECOMMENDED for password hashing' },
  ];
  
  for (const variant of variants) {
    const startTime = Date.now();
    const hash = await argon2.hash(password, {
      type: variant.type,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    const endTime = Date.now();
    
    console.log(`\n${variant.name}:`);
    console.log(`  Description: ${variant.description}`);
    console.log(`  Time: ${endTime - startTime}ms`);
    console.log(`  Hash: ${hash.substring(0, 50)}...`);
  }
  
  console.log('\n💡 Argon2id is recommended for most use cases.');
}

/**
 * Demonstrate memory hardness
 */
async function demonstrateMemoryHardness() {
  console.log('\n🧠 Demonstrating Memory Hardness');
  console.log('=' .repeat(70));
  
  const password = 'TestPassword123!';
  const memoryConfigs = [
    { memoryCost: 2 ** 12, label: '4 MB' },    // 4 MB
    { memoryCost: 2 ** 14, label: '16 MB' },   // 16 MB
    { memoryCost: 2 ** 16, label: '64 MB' },   // 64 MB (recommended)
    { memoryCost: 2 ** 18, label: '256 MB' },  // 256 MB
  ];
  
  console.log('Testing different memory costs:\n');
  
  for (const config of memoryConfigs) {
    const startTime = Date.now();
    await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: config.memoryCost,
      timeCost: 3,
      parallelism: 1,
    });
    const endTime = Date.now();
    
    console.log(`Memory: ${config.label.padEnd(8)} | Time: ${(endTime - startTime).toString().padStart(4)}ms`);
  }
  
  console.log('\n💡 Higher memory cost makes GPU/ASIC attacks more expensive!');
  console.log('   64 MB is recommended for password hashing.');
}

/**
 * Bcrypt vs Argon2 comparison
 */
async function compareBcryptVsArgon2() {
  console.log('\n⚔️  bcrypt vs Argon2 Comparison');
  console.log('=' .repeat(70));
  
  const bcrypt = require('bcrypt');
  const password = 'ComparisonTest123!';
  
  console.log('bcrypt:');
  const bcryptStart = Date.now();
  const bcryptHash = await bcrypt.hash(password, 12);
  const bcryptEnd = Date.now();
  console.log(`  Time: ${bcryptEnd - bcryptStart}ms`);
  console.log(`  Hash: ${bcryptHash}`);
  console.log(`  Memory hardness: ❌ No`);
  console.log(`  GPU resistance: ⚠️  Moderate`);
  
  console.log('\nArgon2id:');
  const argon2Start = Date.now();
  const argon2Hash = await argon2.hash(password, ARGON2_OPTIONS);
  const argon2End = Date.now();
  console.log(`  Time: ${argon2End - argon2Start}ms`);
  console.log(`  Hash: ${argon2Hash}`);
  console.log(`  Memory hardness: ✅ Yes (${ARGON2_OPTIONS.memoryCost / 1024} KB)`);
  console.log(`  GPU resistance: ✅ Excellent`);
  
  console.log('\n🏆 Recommendation:');
  console.log('  - Use Argon2id for NEW applications');
  console.log('  - bcrypt is still secure for existing applications');
  console.log('  - Consider migrating from bcrypt to Argon2 over time');
}

/**
 * Demonstrate secure parameter configuration
 */
async function demonstrateSecureConfig() {
  console.log('\n⚙️  Secure Argon2 Configuration Examples');
  console.log('=' .repeat(70));
  
  const password = 'ConfigTest123!';
  
  const configs = [
    {
      name: 'Minimum (Fast, Less Secure)',
      options: {
        type: argon2.argon2id,
        memoryCost: 2 ** 12,  // 4 MB
        timeCost: 2,
        parallelism: 1,
      }
    },
    {
      name: 'Recommended (Balanced)',
      options: {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,  // 64 MB
        timeCost: 3,
        parallelism: 1,
      }
    },
    {
      name: 'High Security (Slower)',
      options: {
        type: argon2.argon2id,
        memoryCost: 2 ** 18,  // 256 MB
        timeCost: 5,
        parallelism: 2,
      }
    },
  ];
  
  for (const config of configs) {
    console.log(`\n${config.name}:`);
    console.log(`  Memory: ${config.options.memoryCost / 1024} KB`);
    console.log(`  Time cost: ${config.options.timeCost}`);
    console.log(`  Parallelism: ${config.options.parallelism}`);
    
    const startTime = Date.now();
    await argon2.hash(password, config.options);
    const endTime = Date.now();
    
    console.log(`  ⏱️  Hashing time: ${endTime - startTime}ms`);
  }
  
  console.log('\n💡 Choose configuration based on your security needs and hardware.');
}

/**
 * Main demonstration
 */
async function main() {
  console.log('🚀 Argon2 Password Security Demo');
  console.log('=' .repeat(70));
  
  try {
    // 1. Compare Argon2 variants
    await compareArgon2Variants();
    
    // 2. Demonstrate memory hardness
    await demonstrateMemoryHardness();
    
    // 3. Compare bcrypt vs Argon2
    await compareBcryptVsArgon2();
    
    // 4. Demonstrate secure configuration
    await demonstrateSecureConfig();
    
    // 5. Register and login users
    console.log('\n\n👥 User Registration & Login');
    console.log('=' .repeat(70));
    
    await registerUser('alice', 'AliceSecurePass123!');
    await registerUser('bob', 'BobStrongPassword456!');
    
    // Login tests
    await loginUser('alice', 'AliceSecurePass123!');
    
    try {
      await loginUser('bob', 'WrongPassword');
    } catch (error) {
      console.log(`⚠️  Expected error: ${error.message}`);
    }
    
    console.log('\n\n✅ Demo completed successfully!');
    console.log('\n🎯 Key Takeaways:');
    console.log('  1. Argon2id is the most secure password hashing algorithm');
    console.log('  2. Memory hardness protects against GPU/ASIC attacks');
    console.log('  3. Use 64 MB memory cost for good security/performance balance');
    console.log('  4. Argon2 is recommended by OWASP and won the Password Hashing Competition');
    
  } catch (error) {
    console.error('❌ Demo failed:', error);
  }
}

// Run the demo
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { registerUser, loginUser, ARGON2_OPTIONS };
