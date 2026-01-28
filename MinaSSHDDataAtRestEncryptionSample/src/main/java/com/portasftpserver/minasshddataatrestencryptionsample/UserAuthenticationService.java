package com.portasftpserver.minasshddataatrestencryptionsample;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * User authentication with PBKDF2-HMAC-SHA256
 */
public class UserAuthenticationService {
    
    private static final int ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 32;
    
    private static final Map<String, UserCredentials> users = new ConcurrentHashMap<>();
    
    static {
        try {
            addUser("admin", "admin123");
            addUser("testuser", "password123");
            System.out.println("[USERS] Default users initialized");
        } catch (Exception e) {
            System.err.println("[USERS] Initialization failed: " + e.getMessage());
        }
    }
    
    public static boolean authenticate(String username, String password) {
        if (username == null || password == null) return false;
        
        UserCredentials creds = users.get(username);
        if (creds == null) {
            dummyHash(password);
            return false;
        }
        
        try {
            byte[] hash = hashPassword(password, creds.salt);
            return constantTimeEquals(hash, creds.hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }
    }
    
    public static void addUser(String username, String password) throws Exception {
        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        byte[] salt = generateSalt();
        byte[] hash = hashPassword(password, salt);
        users.put(username, new UserCredentials(hash, salt));
    }
    
    private static byte[] hashPassword(String password, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
    
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    private static void dummyHash(String password) {
        try {
            hashPassword(password, new byte[SALT_LENGTH]);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Ignore
        }
    }
    
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    private static class UserCredentials {
        final byte[] hash;
        final byte[] salt;
        
        UserCredentials(byte[] hash, byte[] salt) {
            this.hash = hash;
            this.salt = salt;
        }
    }
}