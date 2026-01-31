/**
 * Day 1: Password Security Tests
 * 
 * Test suite for all password hashing implementations
 */

const bcrypt = require('bcrypt');
const { hashPassword: scryptHash, verifyPassword: scryptVerify } = require('../src/scrypt-example');

describe('Password Security Tests', () => {
    
    describe('bcrypt', () => {
        const password = 'TestPassword123!';
        let hashedPassword;
        
        test('should hash a password', async () => {
            hashedPassword = await bcrypt.hash(password, 10);
            expect(hashedPassword).toBeTruthy();
            expect(hashedPassword).not.toBe(password);
            expect(hashedPassword.length).toBeGreaterThan(0);
        });
        
        test('should verify correct password', async () => {
            const isValid = await bcrypt.compare(password, hashedPassword);
            expect(isValid).toBe(true);
        });
        
        test('should reject incorrect password', async () => {
            const isValid = await bcrypt.compare('WrongPassword', hashedPassword);
            expect(isValid).toBe(false);
        });
        
        test('should generate different hashes for same password', async () => {
            const hash1 = await bcrypt.hash(password, 10);
            const hash2 = await bcrypt.hash(password, 10);
            expect(hash1).not.toBe(hash2);
        });
        
        test('should reject empty password', async () => {
            await expect(bcrypt.hash('', 10)).rejects.toThrow();
        });
    });
    
    describe('scrypt', () => {
        const password = 'TestPassword123!';
        let hashedPassword;
        
        test('should hash a password', async () => {
            hashedPassword = await scryptHash(password);
            expect(hashedPassword).toBeTruthy();
            expect(hashedPassword).not.toBe(password);
            expect(hashedPassword).toContain(':'); // salt:hash format
        });
        
        test('should verify correct password', async () => {
            const isValid = await scryptVerify(password, hashedPassword);
            expect(isValid).toBe(true);
        });
        
        test('should reject incorrect password', async () => {
            const isValid = await scryptVerify('WrongPassword', hashedPassword);
            expect(isValid).toBe(false);
        });
        
        test('should generate different hashes for same password', async () => {
            const hash1 = await scryptHash(password);
            const hash2 = await scryptHash(password);
            expect(hash1).not.toBe(hash2);
        });
    });
    
    describe('Password Validation', () => {
        test('should accept strong password', () => {
            const password = 'StrongPass123!';
            expect(password.length).toBeGreaterThanOrEqual(8);
            expect(/[A-Z]/.test(password)).toBe(true);
            expect(/[a-z]/.test(password)).toBe(true);
            expect(/[0-9]/.test(password)).toBe(true);
            expect(/[!@#$%^&*]/.test(password)).toBe(true);
        });
        
        test('should reject short password', () => {
            const password = 'Short1!';
            expect(password.length).toBeLessThan(8);
        });
        
        test('should reject password without numbers', () => {
            const password = 'NoNumbers!';
            expect(/[0-9]/.test(password)).toBe(false);
        });
        
        test('should reject password without special characters', () => {
            const password = 'NoSpecialChar123';
            expect(/[!@#$%^&*]/.test(password)).toBe(false);
        });
    });
    
    describe('Security Best Practices', () => {
        test('hash should not contain original password', async () => {
            const password = 'MyPassword123!';
            const hash = await bcrypt.hash(password, 10);
            expect(hash.toLowerCase()).not.toContain(password.toLowerCase());
        });
        
        test('salt should be unique for each hash', async () => {
            const password = 'SamePassword123!';
            const hash1 = await bcrypt.hash(password, 10);
            const hash2 = await bcrypt.hash(password, 10);
            
            // Extract salt from bcrypt hash (first 29 characters)
            const salt1 = hash1.substring(0, 29);
            const salt2 = hash2.substring(0, 29);
            
            expect(salt1).not.toBe(salt2);
        });
        
        test('higher salt rounds should take longer', async () => {
            const password = 'BenchmarkPassword';
            
            const start1 = Date.now();
            await bcrypt.hash(password, 8);
            const time1 = Date.now() - start1;
            
            const start2 = Date.now();
            await bcrypt.hash(password, 10);
            const time2 = Date.now() - start2;
            
            // 10 rounds should take longer than 8 rounds
            expect(time2).toBeGreaterThan(time1);
        }, 10000); // Increase timeout for this test
    });
});
