/**
 * Password Hash Migration Example
 * 
 * This demonstrates how to migrate from:
 * 1. Plain text passwords → bcrypt
 * 2. MD5/SHA hashes → bcrypt
 * 3. Old bcrypt (low rounds) → bcrypt (higher rounds)
 * 4. bcrypt → Argon2
 * 
 * Migration strategies:
 * - During login (lazy migration)
 * - Batch migration
 * - Forced password reset
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

/**
 * Simulated legacy database with users using different hash types
 */
const legacyUsers = [
  {
    id: 1,
    username: 'alice',
    password: 'PlainTextPassword123', // 😱 PLAIN TEXT
    hashType: 'plain'
  },
  {
    id: 2,
    username: 'bob',
    password: '5f4dcc3b5aa765d61d8327deb882cf99', // MD5 hash of "password"
    hashType: 'md5'
  },
  {
    id: 3,
    username: 'charlie',
    password: await bcrypt.hash('Charlie123!', 4), // bcrypt with only 4 rounds
    hashType: 'bcrypt_weak'
  },
  {
    id: 4,
    username: 'dave',
    password: await bcrypt.hash('Dave456!', 12), // bcrypt with 12 rounds (good!)
    hashType: 'bcrypt'
  }
];

// Modern secure storage
const modernUsers = [];

const TARGET_BCRYPT_ROUNDS = 12;
const TARGET_ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 3,
  parallelism: 1
};

/**
 * Strategy 1: Lazy Migration During Login
 * Migrate passwords when users log in
 */
async function lazyMigrationLogin(username, password) {
  console.log(`\n🔓 Login attempt: ${username}`);
  
  // Find user in legacy database
  const legacyUser = legacyUsers.find(u => u.username === username);
  
  if (!legacyUser) {
    console.log('❌ User not found');
    return null;
  }
  
  let isValid = false;
  
  // Verify password based on hash type
  switch (legacyUser.hashType) {
    case 'plain':
      console.log('⚠️  User has PLAIN TEXT password - upgrading...');
      isValid = (password === legacyUser.password);
      break;
      
    case 'md5':
      console.log('⚠️  User has MD5 hash - upgrading...');
      const md5Hash = crypto.createHash('md5').update(password).digest('hex');
      isValid = (md5Hash === legacyUser.password);
      break;
      
    case 'bcrypt_weak':
      console.log('⚠️  User has weak bcrypt hash - upgrading...');
      isValid = await bcrypt.compare(password, legacyUser.password);
      break;
      
    case 'bcrypt':
      console.log('✅ User has strong bcrypt hash');
      isValid = await bcrypt.compare(password, legacyUser.password);
      
      // Check if rounds need upgrade
      const currentRounds = getRoundsFromBcryptHash(legacyUser.password);
      if (currentRounds < TARGET_BCRYPT_ROUNDS) {
        console.log(`⚠️  bcrypt rounds too low (${currentRounds}) - upgrading to ${TARGET_BCRYPT_ROUNDS}...`);
        // Will be upgraded below
      } else {
        console.log(`✅ bcrypt rounds optimal (${currentRounds})`);
        return { id: legacyUser.id, username: legacyUser.username };
      }
      break;
  }
  
  if (!isValid) {
    console.log('❌ Invalid password');
    return null;
  }
  
  // Password is valid - migrate to strong hash
  console.log('🔄 Migrating password to bcrypt with 12 rounds...');
  const newHash = await bcrypt.hash(password, TARGET_BCRYPT_ROUNDS);
  
  // Update user in modern database
  const modernUser = {
    id: legacyUser.id,
    username: legacyUser.username,
    passwordHash: newHash,
    hashType: 'bcrypt',
    migratedAt: new Date().toISOString()
  };
  
  modernUsers.push(modernUser);
  
  // Remove from legacy database
  const index = legacyUsers.findIndex(u => u.id === legacyUser.id);
  if (index > -1) {
    legacyUsers.splice(index, 1);
  }
  
  console.log('✅ Password migrated successfully!');
  return { id: modernUser.id, username: modernUser.username };
}

/**
 * Get bcrypt rounds from hash
 */
function getRoundsFromBcryptHash(hash) {
  // bcrypt hash format: $2b$rounds$salthash
  const parts = hash.split('$');
  return parseInt(parts[2], 10);
}

/**
 * Strategy 2: Wrap Existing Hashes
 * When you can't access plain passwords, wrap old hashes with bcrypt
 */
async function wrapLegacyHash(username, password) {
  console.log(`\n🔓 Wrap migration login: ${username}`);
  
  const user = legacyUsers.find(u => u.username === username);
  
  if (!user) {
    return null;
  }
  
  if (user.hashType === 'md5') {
    // First verify with MD5
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');
    
    if (md5Hash !== user.password) {
      console.log('❌ Invalid password');
      return null;
    }
    
    console.log('⚠️  MD5 hash detected');
    console.log('🔄 Wrapping MD5 hash with bcrypt...');
    
    // Wrap the MD5 hash with bcrypt
    const wrappedHash = await bcrypt.hash(user.password, TARGET_BCRYPT_ROUNDS);
    
    // Update user with wrapped hash
    user.password = wrappedHash;
    user.hashType = 'md5_wrapped';
    user.originalMd5 = md5Hash;
    
    console.log('✅ MD5 hash wrapped with bcrypt!');
    console.log('💡 On next login, migrate to pure bcrypt');
    
    return { id: user.id, username: user.username };
  }
  
  if (user.hashType === 'md5_wrapped') {
    // Verify wrapped hash
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');
    const wrappedIsValid = await bcrypt.compare(user.originalMd5, user.password);
    
    if (!wrappedIsValid) {
      return null;
    }
    
    console.log('🔄 Converting wrapped hash to pure bcrypt...');
    const pureHash = await bcrypt.hash(password, TARGET_BCRYPT_ROUNDS);
    
    user.password = pureHash;
    user.hashType = 'bcrypt';
    delete user.originalMd5;
    
    console.log('✅ Fully migrated to bcrypt!');
    return { id: user.id, username: user.username };
  }
  
  return null;
}

/**
 * Strategy 3: Migrate bcrypt to Argon2
 */
async function migrateBcryptToArgon2(username, password) {
  console.log(`\n🔓 Argon2 migration login: ${username}`);
  
  const user = legacyUsers.find(u => u.username === username);
  
  if (!user || user.hashType !== 'bcrypt') {
    return null;
  }
  
  // Verify with bcrypt
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    console.log('❌ Invalid password');
    return null;
  }
  
  console.log('✅ bcrypt verification successful');
  console.log('🔄 Upgrading to Argon2id...');
  
  // Migrate to Argon2
  const argon2Hash = await argon2.hash(password, TARGET_ARGON2_OPTIONS);
  
  const modernUser = {
    id: user.id,
    username: user.username,
    passwordHash: argon2Hash,
    hashType: 'argon2id',
    migratedAt: new Date().toISOString(),
    previousHashType: 'bcrypt'
  };
  
  modernUsers.push(modernUser);
  
  // Remove from legacy
  const index = legacyUsers.findIndex(u => u.id === user.id);
  if (index > -1) {
    legacyUsers.splice(index, 1);
  }
  
  console.log('✅ Successfully migrated to Argon2id!');
  return { id: modernUser.id, username: modernUser.username };
}

/**
 * Strategy 4: Force Password Reset for All Users
 * Send email to all users requiring password reset
 */
async function forcePasswordReset() {
  console.log('\n📧 Force Password Reset Strategy');
  console.log('='.repeat(70));
  
  console.log(`\nFound ${legacyUsers.length} users with legacy password hashes`);
  console.log('Sending password reset emails...\n');
  
  legacyUsers.forEach(user => {
    // In production, send actual email
    console.log(`📧 Email sent to ${user.username}`);
    console.log(`   "Your account security is being upgraded."`);
    console.log(`   "Please reset your password: https://example.com/reset/${user.id}"`);
  });
  
  console.log('\n✅ All users notified');
  console.log('💡 This is the safest but most disruptive method');
}

/**
 * Display migration statistics
 */
function displayMigrationStats() {
  console.log('\n📊 Migration Statistics');
  console.log('='.repeat(70));
  
  const legacyStats = legacyUsers.reduce((acc, user) => {
    acc[user.hashType] = (acc[user.hashType] || 0) + 1;
    return acc;
  }, {});
  
  const modernStats = modernUsers.reduce((acc, user) => {
    acc[user.hashType] = (acc[user.hashType] || 0) + 1;
    return acc;
  }, {});
  
  console.log('\nLegacy Users (needs migration):');
  Object.entries(legacyStats).forEach(([type, count]) => {
    console.log(`  ${type}: ${count} users`);
  });
  
  console.log('\nModern Users (migrated):');
  if (Object.keys(modernStats).length === 0) {
    console.log('  None yet');
  } else {
    Object.entries(modernStats).forEach(([type, count]) => {
      console.log(`  ${type}: ${count} users`);
    });
  }
  
  const totalLegacy = legacyUsers.length;
  const totalModern = modernUsers.length;
  const totalUsers = totalLegacy + totalModern;
  const migrationPercent = totalUsers > 0 ? (totalModern / totalUsers * 100).toFixed(1) : 0;
  
  console.log(`\nMigration Progress: ${migrationPercent}% (${totalModern}/${totalUsers} users)`);
}

/**
 * Main demonstration
 */
async function main() {
  console.log('🚀 Password Hash Migration Demo');
  console.log('='.repeat(70));
  
  try {
    // Initial stats
    console.log('\n📋 Initial Database State:');
    displayMigrationStats();
    
    // Strategy 1: Lazy migration during login
    console.log('\n\n🔄 Strategy 1: Lazy Migration During Login');
    console.log('='.repeat(70));
    
    await lazyMigrationLogin('alice', 'PlainTextPassword123');
    displayMigrationStats();
    
    await lazyMigrationLogin('bob', 'password');
    displayMigrationStats();
    
    await lazyMigrationLogin('charlie', 'Charlie123!');
    displayMigrationStats();
    
    // Try wrong password
    console.log('\n');
    await lazyMigrationLogin('dave', 'WrongPassword');
    
    // Correct password
    await lazyMigrationLogin('dave', 'Dave456!');
    displayMigrationStats();
    
    // Strategy 4: Force reset (demonstration only)
    console.log('\n\n');
    console.log('🔄 Strategy 4: Force Password Reset (Alternative Approach)');
    console.log('='.repeat(70));
    console.log('Note: This would be used if we had many legacy users remaining');
    // await forcePasswordReset(); // Commented out as we've already migrated everyone
    
    console.log('\n\n✅ Migration demo completed!');
    console.log('\n🎯 Key Takeaways:');
    console.log('  1. Lazy migration is least disruptive (upgrade during login)');
    console.log('  2. Wrapping is useful when you can\'t access plain passwords');
    console.log('  3. Force reset is safest but most disruptive');
    console.log('  4. Always upgrade incrementally, not all at once');
    console.log('  5. Monitor migration progress and set target dates');
    console.log('  6. Keep detailed logs of who has/hasn\'t migrated');
    
  } catch (error) {
    console.error('❌ Demo failed:', error);
  }
}

// Run the demo
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  lazyMigrationLogin,
  wrapLegacyHash,
  migrateBcryptToArgon2,
  forcePasswordReset
};
