/**
 * Password Strength Validator
 * 
 * Demonstrates how to:
 * 1. Validate password strength
 * 2. Provide helpful feedback to users
 * 3. Check against common passwords
 * 4. Implement custom password policies
 */

const validator = require('validator');

/**
 * Common passwords list (top 100 most common)
 * In production, use a larger list or a service like Have I Been Pwned
 */
const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 
  '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
  'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
  '123123', '654321', 'superman', 'qazwsx', 'michael', 'football',
  'password1', 'Password1', 'welcome', 'admin', 'login', 'password123'
]);

/**
 * Calculate password entropy (randomness)
 * Higher entropy = stronger password
 */
function calculateEntropy(password) {
  let charsetSize = 0;
  
  if (/[a-z]/.test(password)) charsetSize += 26; // lowercase
  if (/[A-Z]/.test(password)) charsetSize += 26; // uppercase
  if (/[0-9]/.test(password)) charsetSize += 10; // numbers
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32; // special chars
  
  // Entropy = log2(charsetSize^length)
  const entropy = password.length * Math.log2(charsetSize);
  
  return Math.round(entropy);
}

/**
 * Estimate time to crack password using brute force
 */
function estimateCrackTime(password) {
  const entropy = calculateEntropy(password);
  
  // Assume attacker can try 10 billion passwords per second (modern GPU)
  const attemptsPerSecond = 10_000_000_000;
  const possibleCombinations = Math.pow(2, entropy);
  const secondsToCrack = possibleCombinations / attemptsPerSecond / 2; // /2 for average
  
  // Convert to human-readable time
  if (secondsToCrack < 1) return 'Instantly';
  if (secondsToCrack < 60) return `${Math.round(secondsToCrack)} seconds`;
  if (secondsToCrack < 3600) return `${Math.round(secondsToCrack / 60)} minutes`;
  if (secondsToCrack < 86400) return `${Math.round(secondsToCrack / 3600)} hours`;
  if (secondsToCrack < 31536000) return `${Math.round(secondsToCrack / 86400)} days`;
  if (secondsToCrack < 31536000 * 100) return `${Math.round(secondsToCrack / 31536000)} years`;
  return 'Centuries';
}

/**
 * Check if password contains common patterns
 */
function hasCommonPatterns(password) {
  const patterns = {
    sequential: /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i,
    repeated: /(.)\1{2,}/,
    keyboard: /(?:qwerty|asdfgh|zxcvbn|qwertz|azerty)/i,
  };
  
  const found = [];
  
  if (patterns.sequential.test(password)) found.push('sequential characters');
  if (patterns.repeated.test(password)) found.push('repeated characters');
  if (patterns.keyboard.test(password)) found.push('keyboard patterns');
  
  return found;
}

/**
 * Comprehensive password strength checker
 */
function checkPasswordStrength(password, username = '') {
  const result = {
    isValid: false,
    score: 0,
    strength: 'Weak',
    feedback: [],
    warnings: [],
    suggestions: [],
    entropy: 0,
    crackTime: '',
  };
  
  // Basic checks
  const length = password.length;
  const hasLowerCase = /[a-z]/.test(password);
  const hasUpperCase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  
  // Calculate entropy and crack time
  result.entropy = calculateEntropy(password);
  result.crackTime = estimateCrackTime(password);
  
  // Scoring system (0-100)
  let score = 0;
  
  // Length scoring
  if (length >= 8) score += 20;
  if (length >= 12) score += 10;
  if (length >= 16) score += 10;
  
  // Character variety scoring
  if (hasLowerCase) score += 10;
  if (hasUpperCase) score += 10;
  if (hasNumbers) score += 10;
  if (hasSpecialChars) score += 15;
  
  // Entropy bonus
  if (result.entropy >= 50) score += 10;
  if (result.entropy >= 75) score += 15;
  
  // Penalties
  const lowerPassword = password.toLowerCase();
  
  // Common password check
  if (COMMON_PASSWORDS.has(lowerPassword)) {
    score -= 50;
    result.warnings.push('This is a commonly used password');
    result.suggestions.push('Choose a unique password');
  }
  
  // Username in password check
  if (username && lowerPassword.includes(username.toLowerCase())) {
    score -= 30;
    result.warnings.push('Password contains your username');
    result.suggestions.push('Avoid using personal information');
  }
  
  // Pattern checks
  const patterns = hasCommonPatterns(password);
  if (patterns.length > 0) {
    score -= 15;
    result.warnings.push(`Contains ${patterns.join(', ')}`);
    result.suggestions.push('Avoid predictable patterns');
  }
  
  // Minimum requirements feedback
  if (length < 8) {
    result.feedback.push('❌ Password must be at least 8 characters');
  } else {
    result.feedback.push('✅ Length requirement met');
  }
  
  if (!hasLowerCase) {
    result.feedback.push('❌ Add lowercase letters (a-z)');
  } else {
    result.feedback.push('✅ Contains lowercase letters');
  }
  
  if (!hasUpperCase) {
    result.feedback.push('❌ Add uppercase letters (A-Z)');
  } else {
    result.feedback.push('✅ Contains uppercase letters');
  }
  
  if (!hasNumbers) {
    result.feedback.push('❌ Add numbers (0-9)');
  } else {
    result.feedback.push('✅ Contains numbers');
  }
  
  if (!hasSpecialChars) {
    result.feedback.push('❌ Add special characters (!@#$%...)');
  } else {
    result.feedback.push('✅ Contains special characters');
  }
  
  // Ensure score is between 0-100
  result.score = Math.max(0, Math.min(100, score));
  
  // Determine strength level
  if (result.score < 30) {
    result.strength = 'Very Weak';
    result.isValid = false;
  } else if (result.score < 50) {
    result.strength = 'Weak';
    result.isValid = false;
  } else if (result.score < 70) {
    result.strength = 'Moderate';
    result.isValid = true;
  } else if (result.score < 85) {
    result.strength = 'Strong';
    result.isValid = true;
  } else {
    result.strength = 'Very Strong';
    result.isValid = true;
  }
  
  // Additional suggestions
  if (result.isValid && result.score < 85) {
    result.suggestions.push('Consider making it longer for extra security');
  }
  
  if (length < 12) {
    result.suggestions.push('Use at least 12 characters for better security');
  }
  
  return result;
}

/**
 * Generate a strong password
 */
function generateStrongPassword(length = 16) {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  const allChars = lowercase + uppercase + numbers + special;
  
  let password = '';
  
  // Ensure at least one of each type
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += special[Math.floor(Math.random() * special.length)];
  
  // Fill the rest randomly
  for (let i = password.length; i < length; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

/**
 * Display password strength result in a user-friendly format
 */
function displayStrengthResult(password, username = '') {
  const result = checkPasswordStrength(password, username);
  
  console.log('\n' + '='.repeat(70));
  console.log(`🔐 Password Strength Analysis`);
  console.log('='.repeat(70));
  console.log(`Password: ${'*'.repeat(password.length)}`);
  console.log(`\nStrength: ${getStrengthEmoji(result.strength)} ${result.strength}`);
  console.log(`Score: ${result.score}/100 ${getScoreBar(result.score)}`);
  console.log(`Entropy: ${result.entropy} bits`);
  console.log(`Estimated crack time: ${result.crackTime}`);
  
  if (result.feedback.length > 0) {
    console.log(`\n📋 Requirements:`);
    result.feedback.forEach(item => console.log(`   ${item}`));
  }
  
  if (result.warnings.length > 0) {
    console.log(`\n⚠️  Warnings:`);
    result.warnings.forEach(warning => console.log(`   • ${warning}`));
  }
  
  if (result.suggestions.length > 0) {
    console.log(`\n💡 Suggestions:`);
    result.suggestions.forEach(suggestion => console.log(`   • ${suggestion}`));
  }
  
  console.log('='.repeat(70));
}

/**
 * Helper: Get emoji for strength level
 */
function getStrengthEmoji(strength) {
  const emojis = {
    'Very Weak': '🔴',
    'Weak': '🟠',
    'Moderate': '🟡',
    'Strong': '🟢',
    'Very Strong': '🔵',
  };
  return emojis[strength] || '';
}

/**
 * Helper: Get visual score bar
 */
function getScoreBar(score) {
  const barLength = 20;
  const filledLength = Math.round((score / 100) * barLength);
  const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
  return `[${bar}]`;
}

/**
 * Main demonstration
 */
function main() {
  console.log('🚀 Password Strength Validator Demo');
  
  // Test various passwords
  const testPasswords = [
    { password: 'password', username: 'john' },
    { password: '123456', username: 'alice' },
    { password: 'Password1', username: 'bob' },
    { password: 'MyP@ssw0rd', username: 'charlie' },
    { password: 'Tr0ub4dor&3', username: 'dave' },
    { password: 'correct horse battery staple', username: 'eve' },
    { password: 'xK7#mQ9$nL2@pR5!', username: 'frank' },
  ];
  
  testPasswords.forEach(({ password, username }) => {
    displayStrengthResult(password, username);
  });
  
  // Generate and display strong passwords
  console.log('\n\n🎲 Generated Strong Passwords:');
  console.log('='.repeat(70));
  
  for (let i = 0; i < 3; i++) {
    const generated = generateStrongPassword(16);
    console.log(`\nPassword ${i + 1}: ${generated}`);
    const result = checkPasswordStrength(generated);
    console.log(`Strength: ${getStrengthEmoji(result.strength)} ${result.strength} | Score: ${result.score}/100 | Crack time: ${result.crackTime}`);
  }
  
  console.log('\n✅ Demo completed!');
}

// Run the demo
if (require.main === module) {
  main();
}

module.exports = { 
  checkPasswordStrength, 
  generateStrongPassword,
  calculateEntropy,
  estimateCrackTime 
};
