package com.portasftpserver.minasshddataatrestencryptionsample;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

/**
 * SFTP Server with chunked streaming encryption.
 * 
 * Apache MINA SSHD 2.16.0 + Google Tink 1.20.0
 * 
 * Features:
 * - Chunk-based encryption (default 64KB chunks)
 * - Streaming processing (no full file in memory)
 * - Random access support for large files
 * - Zero plaintext on disk
 * - Configurable chunk size and extension mode
 */
public class ChunkedEncryptedSftpServer {
    
    private static final int DEFAULT_PORT = 2222;
    private static final int DEFAULT_CHUNK_SIZE = 64 * 1024; // 64KB
    private static final boolean DEFAULT_USE_ENC_EXTENSION = false;
    
    private final SshServer sshd;
    private final ChunkedEncryptionService crypto;
    private final Path storageRoot;
    private final boolean useEncExtension;
    private final int chunkSize;
    
    /**
     * @param port Server port
     * @param storageRoot Storage root directory
     * @param keysetPath Encryption keyset path
     * @param useEncExtension true = files stored as filename.ext.enc, false = filename.ext
     * @param chunkSize Chunk size in bytes for encryption
     */
    public ChunkedEncryptedSftpServer(int port, Path storageRoot, Path keysetPath, 
                                     boolean useEncExtension, int chunkSize) throws Exception {
        this.storageRoot =  Paths.get(PathProvider.AppLocation()).resolve(storageRoot);
        this.useEncExtension = useEncExtension;
        this.chunkSize = chunkSize;
        this.crypto = new ChunkedEncryptionService(keysetPath, chunkSize);
        this.sshd = createServer(port);
        
        System.out.println("\n" + "=".repeat(70));
        System.out.println("  CHUNKED ENCRYPTED SFTP SERVER");
        System.out.println("=".repeat(70));
        System.out.println("Stack:");
        System.out.println("  - Apache MINA SSHD 2.16.0");
        System.out.println("  - Google Tink 1.15.0 (AES-256-GCM)");
        System.out.println("\nConfiguration:");
        System.out.println("  - Port: " + port);
        System.out.println("  - Storage: " + storageRoot.toAbsolutePath());
        System.out.println("  - Chunk size: " + formatBytes(chunkSize));
        System.out.println("  - Extension mode: " + (useEncExtension ? ".enc suffix" : "no suffix"));
        System.out.println("\nSecurity:");
        System.out.println("  - Encryption: AES-256-GCM (per-chunk authentication)");
        System.out.println("  - Mode: Streaming (zero plaintext on disk)");
        System.out.println("  - Memory usage: ~" + formatBytes(chunkSize * 2) + " per transfer");
        System.out.println("=".repeat(70));
        
        if (useEncExtension) {
            System.out.println("\n⚠️  WARNING: With .enc extension enabled:");
            System.out.println("   - Directory listings will show .enc extensions");
            System.out.println("   - This cannot be hidden in Apache MINA SSHD 2.16.0");
            System.out.println("   - Recommended: Set to false for clean listings\n");
        }
    }
    
    private SshServer createServer(int port) throws IOException {
        Files.createDirectories(storageRoot);
        
        SshServer server = SshServer.setUpDefaultServer();
        server.setPort(port);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser")));
        
        // Password authentication
        server.setPasswordAuthenticator((username, password, session) -> {
            boolean auth = UserAuthenticationService.authenticate(username, password);
            System.out.println("[AUTH] " + username + ": " + (auth ? "✓ SUCCESS" : "✗ FAILED"));
            return auth;
        });
        
        // Virtual file system with user home directories
        VirtualFileSystemFactory fsFactory = new VirtualFileSystemFactory() {
            @Override
            public Path getUserHomeDir(org.apache.sshd.common.session.SessionContext session) 
                    throws IOException {
                String username = session.getUsername();
                Path userDir = storageRoot.resolve(username);
                Files.createDirectories(userDir);
                System.out.println("[FS] User home: " + userDir);
                return userDir;
            }
        };
        server.setFileSystemFactory(fsFactory);
        
        // SFTP subsystem with chunked encryption accessor
        SftpSubsystemFactory sftpFactory = new SftpSubsystemFactory.Builder()
            .withFileSystemAccessor(new ChunkedEncryptedSftpAccessor(crypto, useEncExtension))
            .build();
        
        // Add FRIENDLY event listener (replaces scary EOF exceptions with nice messages)
        sftpFactory.addSftpEventListener(new EncryptedSftpEventListener(useEncExtension));
        
        server.setSubsystemFactories(Collections.singletonList(sftpFactory));
        
        return server;
    }
    
    public void start() throws IOException {
        sshd.start();
        System.out.println("\n" + "=".repeat(70));
        System.out.println("  ✓ SFTP SERVER STARTED");
        System.out.println("=".repeat(70));
        System.out.println("Connection:");
        System.out.println("  sftp -P " + sshd.getPort() + " admin@localhost");
        System.out.println("\nDefault users:");
        System.out.println("  • admin / admin123");
        System.out.println("  • testuser / password123");
        System.out.println("\nFeatures:");
        System.out.println("  • Upload/download with automatic encryption");
        System.out.println("  • Chunk size: " + formatBytes(chunkSize));
        System.out.println("  • Memory efficient: Streams large files");
        System.out.println("  • Random access: Seek support for reads");
        System.out.println("=".repeat(70) + "\n");
    }
    
    public void stop() throws IOException {
        if (sshd != null && sshd.isStarted()) {
            sshd.stop();
            System.out.println("\n[STOP] Server stopped");
        }
    }
    
    public boolean isStarted() {
        return sshd != null && sshd.isStarted();
    }
    
    public int getPort() {
        return sshd.getPort();
    }
    
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024) + " KB";
        return (bytes / (1024 * 1024)) + " MB";
    }
    
    public static void main(String[] args) {
        try {
            // Suppress DEBUG logging to hide internal SSHD EOFExceptions
            // These are normal and expected - not actual errors
            System.setProperty("org.apache.sshd.common.util.logging", "INFO");
            
            // Configuration from system properties or defaults
            int port = Integer.parseInt(
                System.getProperty("sftp.port", String.valueOf(DEFAULT_PORT)));
            
            Path storage = Paths.get(
                System.getProperty("sftp.storage", "sftp-storage"));
            
            Path keyset = Paths.get(
                System.getProperty("sftp.keyset", "keyset.json"));
            
            int chunkSize = Integer.parseInt(
                System.getProperty("sftp.chunk.size", String.valueOf(DEFAULT_CHUNK_SIZE)));
            
            boolean useEncExtension = Boolean.parseBoolean(
                System.getProperty("sftp.use.enc.extension", String.valueOf(DEFAULT_USE_ENC_EXTENSION)));
            
            // Create and start server
            ChunkedEncryptedSftpServer server = new ChunkedEncryptedSftpServer(
                port, storage, keyset, useEncExtension, chunkSize);
            
            // Shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    System.out.println("\n[SHUTDOWN] Stopping server...");
                    server.stop();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }));
            
            server.start();
            
            // Keep running
            Thread.currentThread().join();
            
        } catch (Exception e) {
            System.err.println("\n[ERROR] Server failed to start:");
            System.err.println("  " + e.getMessage());
            System.exit(1);
        }
    }
}