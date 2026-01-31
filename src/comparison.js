/**
 * Day 1: Algorithm Comparison - bcrypt vs Argon2 vs scrypt
 * 
 * This example demonstrates:
 * - Side-by-side comparison of all three algorithms
 * - Performance benchmarks
 * - Security trade-offs
 * - Recommendations for different use cases
 */

const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const { hashPassword: scryptHash, verifyPassword: scryptVerify } = require('./scrypt-example');

console.log('🔒 ALGORITHM COMPARISON: bcrypt vs Argon2 vs scrypt\n');
console.log('='.repeat(70));

/**
 * Configuration for each algorithm
 */
const CONFIGS = {
    bcrypt: {
        saltRounds: 10
    },
    argon2: {
        type: argon2.argon2id,
        memoryCost: 2 ** 16, // 64 MiB
        timeCost: 3,
        parallelism: 1
    },
    scrypt: {
        // Uses default config from scrypt-example.js
    }
};

/**
 * Example 1: Basic Comparison
 */
async function example1_BasicComparison() {
    console.log('\n📝 EXAMPLE 1: Basic Hash Comparison\n');
    
    const password = 'ComparePassword123!';
    
    console.log(`Password to hash: "${password}"\n`);
    
    // Hash with bcrypt
    const bcryptHash = await bcrypt.hash(password, CONFIGS.bcrypt.saltRounds);
    console.log('bcrypt:');
    console.log(`  Hash: ${bcryptHash}`);
    console.log(`  Length: ${bcryptHash.length} characters\n`);
    
    // Hash with Argon2
    const argon2Hash = await argon2.hash(password, CONFIGS.argon2);
    console.log('Argon2:');
    console.log(`  Hash: ${argon2Hash}`);
    console.log(`  Length: ${argon2Hash.length} characters\n`);
    
    // Hash with scrypt
    const scryptHashValue = await scryptHash(password);
    console.log('scrypt:');
    console.log(`  Hash: ${scryptHashValue}`);
    console.log(`  Length: ${scryptHashValue.length} characters\n`);
}

/**
 * Example 2: Performance Benchmark
 */
async function example2_PerformanceBenchmark() {
    console.log('📝 EXAMPLE 2: Performance Benchmark\n');
    
    const password = 'BenchmarkPassword123!';
    const iterations = 10;
    
    console.log(`Running ${iterations} iterations for each algorithm...\n`);
    
    // Benchmark bcrypt
    console.log('⏱️  Testing bcrypt...');
    let bcryptTimes = [];
    for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        await bcrypt.hash(password, CONFIGS.bcrypt.saltRounds);
        bcryptTimes.push(Date.now() - start);
    }
    
    // Benchmark Argon2
    console.log('⏱️  Testing Argon2...');
    let argon2Times = [];
    for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        await argon2.hash(password, CONFIGS.argon2);
        argon2Times.push(Date.now() - start);
    }
    
    // Benchmark scrypt
    console.log('⏱️  Testing scrypt...');
    let scryptTimes = [];
    for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        await scryptHash(password);
        scryptTimes.push(Date.now() - start);
    }
    
    // Calculate averages
    const bcryptAvg = bcryptTimes.reduce((a, b) => a + b) / iterations;
    const argon2Avg = argon2Times.reduce((a, b) => a + b) / iterations;
    const scryptAvg = scryptTimes.reduce((a, b) => a + b) / iterations;
    
    console.log('\n📊 Results (average of 10 runs):\n');
    console.log(`bcrypt:  ${bcryptAvg.toFixed(2)}ms`);
    console.log(`Argon2:  ${argon2Avg.toFixed(2)}ms`);
    console.log(`scrypt:  ${scryptAvg.toFixed(2)}ms`);
    
    // Find fastest and slowest
    const times = { bcrypt: bcryptAvg, Argon2: argon2Avg, scrypt: scryptAvg };
    const fastest = Object.keys(times).reduce((a, b) => times[a] < times[b] ? a : b);
    const slowest = Object.keys(times).reduce((a, b) => times[a] > times[b] ? a : b);
    
    console.log(`\n🏃 Fastest: ${fastest}`);
    console.log(`🐢 Slowest: ${slowest}`);
    
    console.log('\n💡 Remember: Slower is actually better for security!');
    console.log('   It makes brute-force attacks more time-consuming.');
}

/**
 * Example 3: Memory Usage Comparison
 */
async function example3_MemoryUsage() {
    console.log('\n📝 EXAMPLE 3: Memory Usage Comparison\n');
    
    console.log('Approximate memory usage per hash:\n');
    
    console.log('bcrypt:');
    console.log('  ~4 KiB per hash');
    console.log('  ⚠️  Low memory = vulnerable to GPU attacks\n');
    
    console.log('Argon2 (64 MiB setting):');
    console.log('  ~64 MiB per hash (configurable)');
    console.log('  ✅ High memory = resistant to GPU attacks\n');
    
    console.log('scrypt (N=16384, r=8):');
    const scryptMemory = 128 * 16384 * 8;
    console.log(`  ~${(scryptMemory / 1024 / 1024).toFixed(2)} MiB per hash`);
    console.log('  ✅ Memory-hard = resistant to GPU attacks\n');
    
    console.log('💡 Why memory matters:');
    console.log('   Higher memory usage makes attacks expensive:');
    console.log('   - GPUs have limited memory');
    console.log('   - ASICs are expensive to build with lots of RAM');
    console.log('   - Parallel attacks require more hardware');
}

/**
 * Example 4: Security Features Comparison
 */
async function example4_SecurityFeatures() {
    console.log('\n📝 EXAMPLE 4: Security Features Comparison\n');
    
    const features = {
        'Algorithm': ['bcrypt', 'Argon2', 'scrypt'],
        'Year Introduced': ['1999', '2015', '2009'],
        'Auto Salt': ['✅', '✅', '⚠️ Manual'],
        'Memory-Hard': ['❌ (~4 KiB)', '✅ Configurable', '✅ ~16 MiB'],
        'GPU Resistant': ['⚠️ Moderate', '✅ Excellent', '✅ Good'],
        'ASIC Resistant': ['⚠️ Moderate', '✅ Excellent', '✅ Good'],
        'Configurable Params': ['1 (rounds)', '3 (m,t,p)', '3 (N,r,p)'],
        'OWASP Recommended': ['✅', '✅', '✅'],
        'Node.js Built-in': ['❌', '❌', '✅'],
        'Battle-Tested': ['✅ 25+ years', '⚠️ 9 years', '✅ 15+ years']
    };
    
    // Print table
    const keyWidth = 20;
    console.log('Feature'.padEnd(keyWidth) + ' | bcrypt'.padEnd(15) + ' | Argon2'.padEnd(20) + ' | scrypt');
    console.log('-'.repeat(80));
    
    Object.keys(features).forEach(key => {
        if (key === 'Algorithm') return;
        const values = features[key];
        console.log(
            key.padEnd(keyWidth) + ' | ' +
            values[0].padEnd(13) + ' | ' +
            values[1].padEnd(18) + ' | ' +
            values[2]
        );
    });
}

/**
 * Example 5: Use Case Recommendations
 */
async function example5_UseCaseRecommendations() {
    console.log('\n📝 EXAMPLE 5: Which Algorithm Should You Use?\n');
    
    console.log('🎯 RECOMMENDATION GUIDE:\n');
    
    console.log('Choose bcrypt if:');
    console.log('  ✅ You need a well-established, battle-tested solution');
    console.log('  ✅ Your team is already familiar with bcrypt');
    console.log('  ✅ You have moderate security requirements');
    console.log('  ✅ You want wide library support across languages');
    console.log('  ❌ NOT recommended for high-security applications\n');
    
    console.log('Choose Argon2 if:');
    console.log('  ✅ You need maximum security (e.g., financial, healthcare)');
    console.log('  ✅ GPU/ASIC attacks are a major concern');
    console.log('  ✅ You have servers with sufficient RAM');
    console.log('  ✅ You want the latest, most secure algorithm');
    console.log('  ⭐ BEST CHOICE for new high-security projects\n');
    
    console.log('Choose scrypt if:');
    console.log('  ✅ You want a built-in Node.js solution (no dependencies)');
    console.log('  ✅ You need good security without external libraries');
    console.log('  ✅ You want memory-hard properties');
    console.log('  ✅ You prefer simpler dependency management');
    console.log('  ⭐ BEST CHOICE for Node.js-only projects wanting no deps\n');
}

/**
 * Example 6: Migration Strategy
 */
async function example6_MigrationStrategy() {
    console.log('\n📝 EXAMPLE 6: Migration Strategy\n');
    
    console.log('How to migrate from bcrypt to Argon2:\n');
    
    console.log('Strategy 1: Gradual Migration (Recommended)');
    console.log('  1. Keep existing bcrypt hashes working');
    console.log('  2. Use Argon2 for all new user registrations');
    console.log('  3. Rehash on successful login:');
    console.log('     - User logs in with password');
    console.log('     - Verify against old bcrypt hash');
    console.log('     - If valid, create new Argon2 hash');
    console.log('     - Replace bcrypt hash with Argon2 hash');
    console.log('  4. Over time, all active users migrate to Argon2\n');
    
    console.log('Example implementation:');
    console.log(`
async function login(email, password) {
    const user = await findUserByEmail(email);
    
    // Detect hash type
    if (user.password.startsWith('$2b$')) {
        // bcrypt hash
        const isValid = await bcrypt.compare(password, user.password);
        if (isValid) {
            // Rehash with Argon2
            const newHash = await argon2.hash(password);
            await updateUserPassword(user.id, newHash);
            return { success: true };
        }
    } else if (user.password.startsWith('$argon2')) {
        // Argon2 hash
        const isValid = await argon2.verify(user.password, password);
        return { success: isValid };
    }
    
    return { success: false };
}
    `.trim());
}

/**
 * Example 7: Real-World Performance Impact
 */
async function example7_RealWorldImpact() {
    console.log('\n\n📝 EXAMPLE 7: Real-World Attack Scenarios\n');
    
    console.log('Scenario: Attacker tries to crack 1 million passwords\n');
    
    const passwordsToTry = 1000000;
    
    // Assume hardware: 8-core CPU, 16GB RAM
    console.log('Assumptions:');
    console.log('  - Attacker has 8-core CPU, 16GB RAM');
    console.log('  - Stolen database with 1,000 user password hashes');
    console.log('  - Trying common passwords (dictionary attack)\n');
    
    console.log('bcrypt (10 rounds, ~65ms per hash):');
    const bcryptTime = (passwordsToTry * 65) / 1000 / 60 / 60;
    console.log(`  Time to try 1M passwords: ${bcryptTime.toFixed(1)} hours`);
    console.log(`  Parallel on 8 cores: ${(bcryptTime / 8).toFixed(1)} hours`);
    console.log(`  ⚠️  Fast enough for large-scale attacks\n`);
    
    console.log('Argon2 (64 MiB, ~200ms per hash):');
    const argon2Time = (passwordsToTry * 200) / 1000 / 60 / 60;
    const argon2Parallel = 16384 / 64; // 16GB RAM / 64MB per hash
    console.log(`  Time to try 1M passwords: ${argon2Time.toFixed(1)} hours`);
    console.log(`  Parallel limited by RAM: ${argon2Parallel} hashes at once`);
    console.log(`  Time with parallelization: ${(argon2Time / argon2Parallel).toFixed(1)} hours`);
    console.log(`  ✅ Much slower due to memory constraints\n`);
    
    console.log('scrypt (N=16384, ~80ms per hash):');
    const scryptTime = (passwordsToTry * 80) / 1000 / 60 / 60;
    const scryptParallel = 16384 / 16; // 16GB RAM / 16MB per hash
    console.log(`  Time to try 1M passwords: ${scryptTime.toFixed(1)} hours`);
    console.log(`  Parallel limited by RAM: ${scryptParallel} hashes at once`);
    console.log(`  Time with parallelization: ${(scryptTime / scryptParallel).toFixed(1)} hours`);
    console.log(`  ✅ Significantly slower due to memory constraints\n`);
    
    console.log('💡 Key Takeaway:');
    console.log('   Memory-hard algorithms (Argon2, scrypt) make attacks');
    console.log('   exponentially more expensive and time-consuming!');
}

/**
 * Run all examples
 */
async function runAllExamples() {
    try {
        await example1_BasicComparison();
        await example2_PerformanceBenchmark();
        await example3_MemoryUsage();
        await example4_SecurityFeatures();
        await example5_UseCaseRecommendations();
        await example6_MigrationStrategy();
        await example7_RealWorldImpact();
        
        console.log('\n' + '='.repeat(70));
        console.log('✅ All comparisons completed!');
        console.log('='.repeat(70));
        console.log('\n🎯 FINAL RECOMMENDATION:');
        console.log('   → New projects: Use Argon2id');
        console.log('   → Node.js only: Use scrypt (no dependencies)');
        console.log('   → Legacy systems: Stick with bcrypt or migrate gradually');
        console.log('='.repeat(70));
        
    } catch (error) {
        console.error('\n❌ Error running examples:', error.message);
    }
}

// Run if this file is executed directly
if (require.main === module) {
    runAllExamples();
}

module.exports = {
    example1_BasicComparison,
    example2_PerformanceBenchmark,
    example3_MemoryUsage,
    example4_SecurityFeatures,
    example5_UseCaseRecommendations,
    example6_MigrationStrategy,
    example7_RealWorldImpact
};
