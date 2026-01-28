# Data At Rest Encryption (DARE) SFTP Server Implementation

**Repository**: [https://github.com/PortaSFTPServer/MinaSSHDDataAtRestEncryptionSample](https://github.com/PortaSFTPServer/MinaSSHDDataAtRestEncryptionSample)

---

## ⚠️ IMPORTANT NOTICE

**This implementation is intended for educational, development, and testing purposes only.**

This code demonstrates Data At Rest Encryption concepts with Apache MINA SSHD and Google Tink. Before using in production:

- **Replace hardcoded master key** with proper KMS integration
- **Implement production-grade user authentication** (database, LDAP, or SSO)
- **Add comprehensive audit logging** for compliance requirements
- **Conduct security audit and penetration testing**
- **Review and implement all items in the Security Considerations section**

See [Security Considerations](#security-considerations) for detailed production requirements.

---

## Overview

Production-ready SFTP server with transparent Data At Rest Encryption (DARE) using Apache MINA SSHD 2.17.1 and Google Tink 1.20.0. All files stored on disk are encrypted with AES-256-GCM, ensuring zero plaintext exposure at rest while maintaining full SFTP protocol compatibility.

### Key Features

- **Transparent Encryption**: Files automatically encrypted on write and decrypted on read
- **Chunk-Based Processing**: Large files processed in configurable chunks (default 64KB)
- **Streaming Architecture**: No need to load entire files into memory
- **Random Access Support**: Efficient seeking within encrypted files for downloads
- **Per-Chunk Authentication**: Each chunk independently authenticated with AES-256-GCM
- **Configurable Storage Modes**: Support for transparent or .enc extension-based storage
- **Production Security**: PBKDF2-HMAC-SHA256 for user authentication, encrypted keyset storage

---

## Table of Contents

- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [File Format Specification](#file-format-specification)
- [Core Components](#core-components)
- [Security Architecture](#security-architecture)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Performance Considerations](#performance-considerations)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SFTP Client                              │
│              (FileZilla, WinSCP, sftp CLI, etc.)                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ SFTP Protocol (SSH File Transfer)
                             │
┌────────────────────────────▼────────────────────────────────────┐
│              Apache MINA SSHD Server (2.17.1)                   │
├─────────────────────────────────────────────────────────────────┤
│  - SSH Protocol Handling & Session Management                   │
│  - SFTP Subsystem (File Operations)                             │
│  - User Authentication (Password-based)                         │
│  - Virtual File System (Per-user home directories)              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ File I/O Operations
                             │
┌────────────────────────────▼────────────────────────────────────┐
│          ChunkedEncryptedSftpAccessor                           │
├─────────────────────────────────────────────────────────────────┤
│  - Intercepts all file open operations                          │
│  - Routes to appropriate channel (read/write)                   │
│  - Manages logical vs physical file path mapping                │
│  - Handles .enc extension mode if enabled                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
┌───────────────────────┐   ┌────────────────────────┐
│  ChunkedReadChannel   │   │  ChunkedWriteChannel   │
├───────────────────────┤   ├────────────────────────┤
│ - Random access reads │   │ - Sequential writes    │
│ - Chunk caching       │   │ - Write buffering      │
│ - Seek support        │   │ - Auto-flush on chunk  │
│ - On-demand decrypt   │   │ - Header management    │
└──────────┬────────────┘   └──────────┬─────────────┘
           │                           │
           └──────────┬────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│           ChunkedEncryptionService (Google Tink)                │
├─────────────────────────────────────────────────────────────────┤
│  - AES-256-GCM encryption/decryption                            │
│  - Per-chunk authentication with associated data                │
│  - File header creation and parsing                             │
│  - Keyset management (encrypted with master key)                │
│  - Random access chunk retrieval by index                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Encrypted File Storage                       │
├─────────────────────────────────────────────────────────────────┤
│  Structure: [HEADER][CHUNK_0_SIZE][CHUNK_0]...                  │
│  Location:  ./sftp-storage/<username>/                          │
│  Format:    All data encrypted with AES-256-GCM                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

#### Upload (Write) Flow

```
1. Client sends file via SFTP PUT
2. SSHD routes to ChunkedEncryptedSftpAccessor
3. Accessor creates ChunkedWriteChannel
4. Channel buffers incoming plaintext data
5. When buffer reaches chunk size:
   a. Encrypt chunk with AES-256-GCM
   b. Write [chunk_size][encrypted_data] to disk
   c. Clear buffer
6. On close: flush partial chunk, update header
```

#### Download (Read) Flow

```
1. Client sends file via SFTP GET
2. SSHD routes to ChunkedEncryptedSftpAccessor
3. Accessor creates ChunkedReadChannel
4. Channel reads file header for metadata
5. For each read request:
   a. Calculate chunk index from position
   b. If not cached, decrypt chunk from disk
   c. Copy plaintext data from chunk to client
   d. Update position
6. Return -1 on EOF (critical for SSHD compatibility)
```

---

## Technology Stack

### Core Dependencies

```xml
<dependencies>
    <!-- Apache MINA SSHD -->
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-core</artifactId>
        <version>2.17.1</version>
    </dependency>
    
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-sftp</artifactId>
        <version>2.17.1</version>
    </dependency>
    
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-common</artifactId>
        <version>2.17.1</version>
    </dependency>
    
    <!-- Google Tink Cryptography -->
    <dependency>
        <groupId>com.google.crypto.tink</groupId>
        <artifactId>tink</artifactId>
        <version>1.20.0</version>
    </dependency>
    
    <!-- Logging -->
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.13</version>
    </dependency>
    
    <dependency>
        <groupId>ch.qos.logback</groupId>
        <artifactId>logback-classic</artifactId>
        <version>1.5.6</version>
    </dependency>
</dependencies>
```

### Runtime Requirements

- **Java**: 11 or higher (compiled with Java 11 target)
- **Memory**: Minimum 512MB RAM (recommended 1GB+)
- **Disk**: Depends on storage needs (encrypted files ~1-2% larger than plaintext)
- **Network**: Port 2222 (default, configurable)

---

## File Format Specification

### Encrypted File Structure

```
┌──────────────────────────────────────────────────────────────┐
│                      FILE HEADER (32 bytes)                  │
├──────────────────────────────────────────────────────────────┤
│  Offset  │ Size │ Field            │ Description             │
├──────────┼──────┼──────────────────┼─────────────────────────┤
│  0       │  4   │ Magic            │ "CENC" (0x43454E43)     │
│  4       │  2   │ Version          │ 0x0001                  │
│  6       │  4   │ Chunk Size       │ Default: 65536 bytes    │
│  10      │  8   │ Original Size    │ Plaintext file size     │
│  18      │  14  │ Reserved         │ Random padding          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    CHUNK 0 (Variable Size)                   │
├──────────────────────────────────────────────────────────────┤
│  Chunk Size (4 bytes)    │ Encrypted size (plaintext + tag)  │
│  Encrypted Data (N bytes)│ AES-256-GCM ciphertext            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    CHUNK 1 (Variable Size)                   │
├──────────────────────────────────────────────────────────────┤
│  Chunk Size (4 bytes)    │ Encrypted size                    │
│  Encrypted Data (M bytes)│ AES-256-GCM ciphertext            │
└──────────────────────────────────────────────────────────────┘

... (additional chunks as needed)
```

### Encryption Specification

#### Algorithm Details

- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits
- **IV/Nonce**: 96 bits (automatically generated per chunk by Tink)
- **Authentication Tag**: 128 bits (16 bytes) per chunk
- **Associated Data**: `"<filename>:chunk:<index>"` (e.g., "report.pdf:chunk:0")

#### Per-Chunk Encryption

Each chunk is encrypted independently:

```
Input:  plaintext_chunk (up to 64KB)
AAD:    "filename:chunk:N"
Output: ciphertext || authentication_tag
```

Benefits:
- **Random Access**: Decrypt only needed chunks
- **Integrity**: Each chunk authenticated independently
- **Corruption Isolation**: Bad chunk doesn't affect others
- **Parallelization**: Chunks can be decrypted in parallel (future enhancement)

#### Associated Data Purpose

```
Format: "<filename>:chunk:<index>"
Examples:
  - "document.pdf:chunk:0"
  - "document.pdf:chunk:1"
  - "archive.zip:chunk:42"

Purpose:
  1. Binds encrypted data to specific file
  2. Binds encrypted data to specific position
  3. Prevents chunk reordering attacks
  4. Prevents chunk substitution attacks
```

---

## Core Components

### 1. ChunkedEncryptedSftpServer

**Location**: `ChunkedEncryptedSftpServer.java`

**Purpose**: Main entry point - initializes and manages SFTP server lifecycle

**Key Responsibilities**:
- SSH/SFTP server initialization and configuration
- User authentication setup (PBKDF2)
- Virtual file system configuration (per-user directories)
- Encryption service initialization
- Event listener registration for logging
- Graceful shutdown handling

**Configuration Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sftp.port` | 2222 | Server listening port |
| `sftp.storage` | ./sftp-storage | Root storage directory |
| `sftp.keyset` | ./keyset.json | Encryption keyset path |
| `sftp.chunk.size` | 65536 | Chunk size in bytes (64KB) |
| `sftp.use.enc.extension` | false | Add .enc suffix to encrypted files |

**Usage**:

```java
// Programmatic
ChunkedEncryptedSftpServer server = new ChunkedEncryptedSftpServer(
    2222,                          // port
    Paths.get("./sftp-storage"),   // storage root
    Paths.get("./keyset.json"),    // keyset path
    false,                         // useEncExtension
    64 * 1024                      // chunkSize
);
server.start();

// System properties
java -Dsftp.port=2222 \
     -Dsftp.storage=/data/sftp \
     -Dsftp.keyset=/keys/keyset.json \
     -Dsftp.chunk.size=131072 \
     -jar sftp-server.jar
```

**Server Output Example**:

```
======================================================================
  CHUNKED ENCRYPTED SFTP SERVER
======================================================================
Stack:
  - Apache MINA SSHD 2.17.1
  - Google Tink 1.20.0 (AES-256-GCM)

Configuration:
  - Port: 2222
  - Storage: /home/user/sftp-storage
  - Chunk size: 64 KB
  - Extension mode: no suffix

Security:
  - Encryption: AES-256-GCM (per-chunk authentication)
  - Mode: Streaming (zero plaintext on disk)
  - Memory usage: ~128 KB per transfer
======================================================================
```

---

### 2. ChunkedEncryptedSftpAccessor

**Location**: `ChunkedEncryptedSftpAccessor.java`

**Purpose**: Intercepts SFTP file operations and routes through encryption channels

**Interface**: Implements `SftpFileSystemAccessor` from Apache MINA SSHD

**Key Method**:

```java
@Override
public SeekableByteChannel openFile(
    SftpSubsystemProxy subsystem,
    FileHandle fileHandle,
    Path file,
    String handle,
    Set<? extends OpenOption> options,
    FileAttribute<?>[] attrs
) throws IOException
```

**Operation Logic**:

```
1. Extract filename from path
2. Determine operation mode:
   - READ flag set → read operation
   - WRITE/CREATE flags set → write operation
   - Both set → determine from file existence
3. Map logical filename to physical path:
   - No extension mode: filename.txt → filename.txt (encrypted)
   - Extension mode: filename.txt → filename.txt.enc
4. Return appropriate channel:
   - ChunkedReadChannel for reads
   - ChunkedWriteChannel for writes
```

**Extension Modes**:

#### Mode 1: No Extension (Recommended)

```
Client View:     report.pdf
Physical Disk:   report.pdf (encrypted content)

Advantages:
  - Clean directory listings
  - Transparent to client
  - No filename modifications

Directory Listing:
  drwxr-xr-x  2 admin admin 4096 Jan 27 10:00 .
  drwxr-xr-x  3 admin admin 4096 Jan 27 09:00 ..
  -rw-r--r--  1 admin admin 1024 Jan 27 10:15 report.pdf
  -rw-r--r--  1 admin admin 2048 Jan 27 10:20 data.csv
```

#### Mode 2: With .enc Extension

```
Client View:     report.pdf.enc
Physical Disk:   report.pdf.enc (encrypted content)

Advantages:
  - Explicit encryption indication
  - Easy to identify encrypted files

Disadvantages:
  - Visible .enc suffix
  - Cannot be hidden in MINA SSHD 2.17.1

Directory Listing:
  drwxr-xr-x  2 admin admin 4096 Jan 27 10:00 .
  drwxr-xr-x  3 admin admin 4096 Jan 27 09:00 ..
  -rw-r--r--  1 admin admin 1024 Jan 27 10:15 report.pdf.enc
  -rw-r--r--  1 admin admin 2048 Jan 27 10:20 data.csv.enc
```

---

### 3. ChunkedEncryptionService

**Location**: `ChunkedEncryptionService.java`

**Purpose**: Core encryption/decryption engine using Google Tink

**Key Features**:
- AES-256-GCM encryption with Google Tink
- Keyset management (encrypted storage with master key)
- Header creation and parsing
- Chunk-level encryption/decryption
- Random access chunk retrieval by index

**Constructor**:

```java
public ChunkedEncryptionService(Path keysetPath, int chunkSize) 
    throws GeneralSecurityException, IOException
```

**Core Methods**:

```java
// Encrypt entire stream
public void encryptStream(byte[] plaintext, String filename, OutputStream output)

// Decrypt entire stream
public byte[] decryptStream(InputStream input, String filename)

// Get file metadata
public FileHeader getFileHeader(InputStream input)

// Random access decryption
public byte[] decryptChunkByIndex(RandomAccessFile input, String filename, int chunkIndex)

// Single chunk operations
public byte[] encryptChunk(byte[] chunk, String filename, int chunkIndex)
public byte[] decryptChunk(byte[] encryptedChunk, String filename, int chunkIndex)
```

**Keyset Management**:

The service manages encryption keys using Google Tink's keyset format:

```java
// Keyset storage (encrypted with master key)
{
  "encryptedKeyset": "...",  // Base64-encoded encrypted keyset
  "keysetInfo": {
    "primaryKeyId": 123456789,
    "keyInfo": [...]
  }
}
```

**IMPORTANT SECURITY NOTE** (Educational Implementation):

The current implementation uses a hardcoded master key for demonstration purposes:

```java
// ⚠️ EDUCATIONAL/TESTING ONLY - NOT FOR PRODUCTION ⚠️
byte[] masterKeyBytes = Arrays.copyOf(
    "your-plaintext-password-here".getBytes(StandardCharsets.UTF_8),
    32
);
```

**This is intentionally insecure to simplify the educational example.**

**For ANY deployment beyond local testing, you MUST**:
1. Replace with KMS-based key management
2. Use environment variables or secure vault for master key
3. Implement proper key rotation
4. Add salt to master key derivation

Example production approach:

```java
// Production approach
String masterKey = System.getenv("ENCRYPTION_MASTER_KEY");
if (masterKey == null) {
    throw new IllegalStateException("ENCRYPTION_MASTER_KEY not set");
}

// Derive key with salt (from KMS or secure storage)
byte[] salt = loadSaltFromSecureStorage();
byte[] masterKeyBytes = deriveKeyWithPBKDF2(masterKey, salt);
Aead masterKeyAead = new AesGcmJce(masterKeyBytes);
```

**File Header Class**:

```java
public static class FileHeader {
    public final short version;      // Format version
    public final int chunkSize;      // Chunk size in bytes
    public final long originalSize;  // Original file size
    
    public int getTotalChunks() {
        return (int) Math.ceil((double) originalSize / chunkSize);
    }
}
```

---

### 4. ChunkedEncryptedChannels

**Location**: `ChunkedEncryptedChannels.java`

Contains two specialized `SeekableByteChannel` implementations:

#### 4.1. ChunkedReadChannel

**Purpose**: Random-access read operations with on-demand chunk decryption

**Features**:
- Single-chunk caching (current chunk kept in memory)
- Full seek support (position to any offset in file)
- Proper EOF handling (returns -1, not 0)
- Efficient for large files (only decrypts needed chunks)
- Memory efficient (~64KB overhead per open file)

**Read Algorithm**:

```java
public int read(ByteBuffer dst) {
    // 1. EOF check
    if (position >= fileSize) return -1;
    
    // 2. Calculate chunk and offset
    int chunkIndex = position / chunkSize;
    int offsetInChunk = position % chunkSize;
    
    // 3. Load chunk if not cached
    if (chunkIndex != currentChunkIndex) {
        decryptAndCacheChunk(chunkIndex);
    }
    
    // 4. Copy data from chunk to destination
    int toRead = min(dst.remaining(), chunkData.length - offsetInChunk);
    dst.put(chunkData, offsetInChunk, toRead);
    
    // 5. Update position
    position += toRead;
    
    return toRead;
}
```

**Seek Implementation**:

```java
public SeekableByteChannel position(long newPosition) {
    if (newPosition < 0 || newPosition > fileSize) {
        throw new IllegalArgumentException("Invalid position");
    }
    position = newPosition;
    return this;
}
```

**Critical EOF Handling**:

```java
// CRITICAL: Return -1 (not 0) when at EOF
// SSHD interprets:
//   0  = "try again later" (leads to infinite loop)
//   -1 = "end of stream" (correct termination)

if (position >= fileSize) {
    return -1;  // Proper EOF signal
}
```

**Example Usage Pattern** (internal):

```java
ChunkedReadChannel channel = new ChunkedReadChannel(
    encryptedFile, 
    "document.pdf", 
    cryptoService
);

ByteBuffer buffer = ByteBuffer.allocate(8192);
while (channel.read(buffer) != -1) {
    buffer.flip();
    // Process data
    buffer.clear();
}
channel.close();
```

#### 4.2. ChunkedWriteChannel

**Purpose**: Sequential write operations with automatic chunk encryption

**Features**:
- Write buffering (accumulates data until chunk size)
- Automatic flush on chunk boundary
- Header creation and updates
- Sequential write only (no backward seeking)
- Efficient memory usage

**Write Algorithm**:

```java
public int write(ByteBuffer src) {
    int totalWritten = 0;
    
    while (src.hasRemaining()) {
        // 1. Copy to buffer
        int toBuffer = min(src.remaining(), chunkSize - buffer.size());
        buffer.write(src, toBuffer);
        totalWritten += toBuffer;
        
        // 2. Flush if buffer full
        if (buffer.size() >= chunkSize) {
            encryptAndFlushChunk(false);
        }
    }
    
    return totalWritten;
}
```

**Chunk Flush Process**:

```java
private void flushChunk(boolean isFinal) {
    // 1. Get buffered data
    byte[] plaintext = buffer.toByteArray();
    
    // 2. Encrypt chunk
    String aad = filename + ":chunk:" + chunkIndex;
    byte[] encrypted = crypto.encryptChunk(plaintext, filename, chunkIndex);
    
    // 3. Write to disk: [size][data]
    writeInt(output, encrypted.length);
    output.write(encrypted);
    
    // 4. Reset buffer
    buffer.reset();
    chunkIndex++;
}
```

**Position Management**:

```java
public SeekableByteChannel position(long newPosition) {
    if (newPosition == totalBytesWritten) {
        return this;  // No-op
    }
    
    if (newPosition < totalBytesWritten) {
        throw new IOException("Cannot seek backwards in write channel");
    }
    
    // Forward seek: fill with zeros
    long gap = newPosition - totalBytesWritten;
    byte[] zeros = new byte[(int) min(gap, 8192)];
    ByteBuffer zeroBuf = ByteBuffer.wrap(zeros);
    while (gap > 0) {
        int toWrite = (int) min(gap, zeros.length);
        zeroBuf.limit(toWrite);
        write(zeroBuf);
        gap -= toWrite;
        zeroBuf.clear();
    }
    
    return this;
}
```

**Close and Finalization**:

```java
public void close() {
    // 1. Flush any remaining data
    flushChunk(true);
    
    // 2. Update header with final file size
    updateHeaderSize();
    
    // 3. Close underlying file
    fileOutput.close();
}

private void updateHeaderSize() {
    // Seek to size field in header (offset 10)
    RandomAccessFile raf = new RandomAccessFile(file, "rw");
    raf.seek(10);
    writeLong(raf, totalBytesWritten);
    raf.close();
}
```

---

### 5. EncryptedSftpEventListener

**Location**: `EncryptedSftpEventListener.java`

**Purpose**: User-friendly logging and event monitoring

**Interface**: Implements `SftpEventListener` from Apache MINA SSHD

**Events Tracked**:

| Event | Description | Example Log |
|-------|-------------|-------------|
| `opening` | File opened | `[SFTP-OPEN] admin opened: report.pdf (1.5 MB)` |
| `read` | Data read | `[SFTP-READ] report.pdf: 750 KB / 1.5 MB (50%)` |
| `written` | Data written | `[SFTP-WRITE] upload.zip: 10.0 MB uploaded` |
| `closed` | File closed | `[SFTP-CLOSE] report.pdf closed (total: 1.5 MB)` |
| `removing` | File deleted | `[SFTP-DELETE] admin deleted: old_file.txt` |
| `moving` | File renamed/moved | `[SFTP-MOVE] admin moved: old.txt -> new.txt` |

**EOF Exception Handling**:

Apache MINA SSHD internally throws EOFException during normal read completion. This listener replaces scary stack traces with friendly messages:

```java
@Override
public void read(..., Throwable thrown) {
    if (thrown instanceof EOFException) {
        // Normal EOF - replace with friendly message
        System.out.println("[SFTP-READ] " + filename + 
            ": End of file reached (download complete)");
    } else {
        // Actual error
        System.err.println("[SFTP-ERROR] " + filename + 
            " read failed: " + thrown.getMessage());
    }
}
```

**Before**:
```
java.io.EOFException
    at org.apache.sshd.sftp.server.SftpSubsystem.read(...)
    at org.apache.sshd.sftp.server.SftpSubsystem.process(...)
    ...
```

**After**:
```
[SFTP-READ] document.pdf: End of file reached (download complete)
```

**Progress Logging**:

Logs progress at strategic points to avoid spam:

```java
private boolean shouldLogProgress(long prev, long curr, long total) {
    // Log every 10MB
    if (prev / 10MB != curr / 10MB) return true;
    
    // Log at 25%, 50%, 75% milestones
    int prevPct = (int)((prev * 100) / total);
    int currPct = (int)((curr * 100) / total);
    
    return (prevPct < 25 && currPct >= 25) ||
           (prevPct < 50 && currPct >= 50) ||
           (prevPct < 75 && currPct >= 75);
}
```

**Example Log Sequence**:

```
[SFTP-OPEN] admin opened: largefile.zip (100.0 MB)
[SFTP-READ] largefile.zip: 10.0 MB / 100.0 MB (10%)
[SFTP-READ] largefile.zip: 20.0 MB / 100.0 MB (20%)
[SFTP-READ] largefile.zip: 25.0 MB / 100.0 MB (25%)
[SFTP-READ] largefile.zip: 50.0 MB / 100.0 MB (50%)
[SFTP-READ] largefile.zip: 75.0 MB / 100.0 MB (75%)
[SFTP-READ] largefile.zip: End of file reached (download complete)
[SFTP-CLOSE] largefile.zip closed (total: 100.0 MB)
```

---

### 6. UserAuthenticationService

**Location**: `UserAuthenticationService.java`

**Purpose**: Secure password-based user authentication

**Security Implementation**:

```java
Algorithm:   PBKDF2-HMAC-SHA256
Iterations:  100,000 (OWASP recommendation for 2024)
Salt:        32 bytes (cryptographically random)
Key Length:  256 bits
Storage:     In-memory (ConcurrentHashMap)
```

**Security Features**:

1. **Password Hashing** (PBKDF2):
```java
private static byte[] hashPassword(String password, byte[] salt) {
    PBEKeySpec spec = new PBEKeySpec(
        password.toCharArray(), 
        salt, 
        100000,  // iterations
        256      // key length
    );
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    return factory.generateSecret(spec).getEncoded();
}
```

2. **Constant-Time Comparison** (prevents timing attacks):
```java
private static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) return false;
    
    int result = 0;
    for (int i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];  // Accumulate all differences
    }
    return result == 0;  // Always processes entire array
}
```

3. **Dummy Hash** (prevents username enumeration):
```java
public static boolean authenticate(String username, String password) {
    UserCredentials creds = users.get(username);
    
    if (creds == null) {
        dummyHash(password);  // Same timing as real auth
        return false;
    }
    
    // Real authentication
    byte[] hash = hashPassword(password, creds.salt);
    return constantTimeEquals(hash, creds.hash);
}
```

**Default Users** (For Testing/Development Only):

```java
Username: admin
Password: admin123

Username: testuser
Password: password123
```

**⚠️ WARNING**: These default credentials are for educational and testing purposes only. Remove or change these credentials before any deployment, even in development environments accessible from network.

**Adding New Users**:

```java
// Programmatic
UserAuthenticationService.addUser("newuser", "SecurePass123!");

// Minimum password length: 8 characters
```

**Production Considerations**:

For production, replace in-memory storage with:
- Database with encrypted credentials
- LDAP/Active Directory integration
- OAuth2/OIDC authentication
- Multi-factor authentication (MFA)

Example database integration:

```java
public static boolean authenticate(String username, String password) {
    // Load from database
    UserRecord record = database.loadUser(username);
    if (record == null) {
        dummyHash(password);
        return false;
    }
    
    byte[] hash = hashPassword(password, record.salt);
    return constantTimeEquals(hash, record.passwordHash);
}
```

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Network Security                                       │
│  - SSH protocol encryption (client ← → server transport)        │
│  - Host key verification                                        │
│  - Port-based access control                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Authentication                                         │
│  - PBKDF2-HMAC-SHA256 password hashing (100K iterations)        │
│  - Constant-time comparison (timing attack prevention)          │
│  - Username enumeration prevention                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Application Security                                   │
│  - Input validation on all file operations                      │
│  - Path traversal prevention (virtual file system)              │
│  - Per-user directory isolation                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Data At Rest Encryption (DARE)                         │
│  - AES-256-GCM per-chunk encryption                             │
│  - Per-chunk authentication tags                                │
│  - Associated data binding (prevents chunk attacks)             │
│  - Zero plaintext on disk                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Storage Security                                       │
│  - Encrypted keyset storage                                     │
│  - File system permissions                                      │
│  - Physical security (server hosting environment)               │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Key Hierarchy

```
┌──────────────────────────────────────────────────────────────┐
│              Master Key (from KMS or secure vault)           │
│                    256-bit AES key                           │
└─────────────────────────┬────────────────────────────────────┘
                          │ (encrypts)
                          ↓
┌──────────────────────────────────────────────────────────────┐
│              Data Encryption Keyset (Tink)                   │
│           Stored encrypted in keyset.json                    │
└─────────────────────────┬────────────────────────────────────┘
                          │ (provides)
                          ↓
┌──────────────────────────────────────────────────────────────┐
│         File Encryption Key (AES-256-GCM)                    │
│          Generated by Google Tink, rotatable                 │
└─────────────────────────┬────────────────────────────────────┘
                          │ (encrypts)
                          ↓
┌──────────────────────────────────────────────────────────────┐
│              Individual File Chunks                          │
│      Each chunk: plaintext + AAD → ciphertext + tag          │
└──────────────────────────────────────────────────────────────┘
```

### Threat Model & Mitigations

| Threat | Mitigation |
|--------|------------|
| **Disk theft / unauthorized physical access** | All files encrypted with AES-256-GCM, zero plaintext on disk |
| **Chunk reordering attack** | Associated data includes chunk index, prevents reordering |
| **Chunk substitution attack** | Associated data includes filename, prevents cross-file attacks |
| **Timing attacks on authentication** | Constant-time password comparison |
| **Username enumeration** | Dummy hash performed for invalid usernames |
| **Password brute force** | PBKDF2 with 100K iterations slows attempts |
| **Man-in-the-middle (transport)** | SSH protocol encryption (separate from DARE) |
| **Replay attacks** | GCM nonces prevent ciphertext replay |
| **Chunk corruption** | GCM authentication tags detect tampering |

---

## Installation & Setup

### Prerequisites

```bash
# Java 11 or higher
java -version

# Maven 3.6+ (for building)
mvn -version

# Git (for cloning)
git -version
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/PortaSFTPServer/MinaSSHDDataAtRestEncryptionSample.git
cd MinaSSHDDataAtRestEncryptionSample

# Build with Maven
mvn clean package

# Output: target/MinaSSHDDataAtRestEncryptionSample-1.0-SNAPSHOT.jar
```

### Build Configuration

The `pom.xml` includes Maven Shade Plugin for creating an executable JAR:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-shade-plugin</artifactId>
    <version>3.5.3</version>
    <configuration>
        <transformers>
            <transformer implementation="...ManifestResourceTransformer">
                <mainClass>com.portasftpserver.minasshddataatrestencryptionsample.ChunkedEncryptedSftpServer</mainClass>
            </transformer>
        </transformers>
        <!-- Exclude signature files -->
        <filters>
            <filter>
                <artifact>*:*</artifact>
                <excludes>
                    <exclude>META-INF/*.SF</exclude>
                    <exclude>META-INF/*.DSA</exclude>
                    <exclude>META-INF/*.RSA</exclude>
                </excludes>
            </filter>
        </filters>
    </configuration>
</plugin>
```

### First Run

```bash
# Run with defaults
java -jar target/MinaSSHDDataAtRestEncryptionSample-1.0-SNAPSHOT.jar

# Server will:
# 1. Generate encryption keyset (./keyset.json)
# 2. Create storage directory (./sftp-storage)
# 3. Initialize default users
# 4. Start on port 2222
```

### Directory Structure After First Run

```
project-root/
├── keyset.json                    # Encrypted encryption keyset
├── hostkey.ser                    # SSH host key
├── sftp-storage/                  # Storage root
│   ├── admin/                     # User: admin
│   └── testuser/                  # User: testuser
└── target/
    └── MinaSSHDDataAtRestEncryptionSample-1.0-SNAPSHOT.jar
```

---

## Configuration

### System Properties

Configure server behavior via Java system properties:

```bash
java -Dsftp.port=2222 \
     -Dsftp.storage=/data/sftp \
     -Dsftp.keyset=/keys/keyset.json \
     -Dsftp.chunk.size=131072 \
     -Dsftp.use.enc.extension=false \
     -jar sftp-server.jar
```

### Configuration Reference

| Property | Default | Description | Valid Values |
|----------|---------|-------------|--------------|
| `sftp.port` | 2222 | Server port | 1-65535 |
| `sftp.storage` | ./sftp-storage | Storage root | Any valid path |
| `sftp.keyset` | ./keyset.json | Keyset file | Any valid path |
| `sftp.chunk.size` | 65536 | Chunk size (bytes) | > 0, recommend 64KB-1MB |
| `sftp.use.enc.extension` | false | Use .enc suffix | true / false |

### Chunk Size Selection

| Chunk Size | Use Case | Pros | Cons |
|------------|----------|------|------|
| 16 KB | Small files, low memory | Fast random access | More overhead |
| 64 KB | Default, balanced | Good balance | - |
| 256 KB | Large files | Fewer chunks | Higher memory per file |
| 1 MB | Very large files | Maximum efficiency | Slower random access |

Formula for memory usage per open file:
```
Memory ≈ chunk_size × 2 + overhead
```

Example:
- 64KB chunks: ~130KB per open file
- 256KB chunks: ~520KB per open file

### Production Configuration Example

```bash
#!/bin/bash

# Production SFTP Server Startup Script

# JVM Options
JAVA_OPTS="-Xms1G -Xmx4G \
           -XX:+UseG1GC \
           -XX:MaxGCPauseMillis=200"

# Application Configuration
APP_OPTS="-Dsftp.port=2222 \
          -Dsftp.storage=/data/encrypted-sftp \
          -Dsftp.keyset=/secure/keys/keyset.json \
          -Dsftp.chunk.size=65536 \
          -Dsftp.use.enc.extension=false"

# Logging Configuration
LOG_OPTS="-Dlogback.configurationFile=/etc/sftp/logback.xml"

# Run server
java $JAVA_OPTS $APP_OPTS $LOG_OPTS \
     -jar /opt/sftp-server/sftp-server.jar
```

### Logback Configuration (Optional)

Create `logback.xml` for detailed logging:

```xml
<configuration>
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>/var/log/sftp-server/server.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>/var/log/sftp-server/server.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="FILE" />
    </root>
    
    <!-- Suppress SSHD debug messages -->
    <logger name="org.apache.sshd" level="WARN" />
</configuration>
```

---

## Usage Examples

### Connecting with SFTP Client

#### Command Line (sftp)

```bash
# Connect to server
sftp -P 2222 admin@localhost

# Commands
sftp> ls                    # List files
sftp> pwd                   # Print working directory
sftp> put localfile.txt     # Upload file
sftp> get remotefile.txt    # Download file
sftp> rm oldfile.txt        # Delete file
sftp> rename old.txt new.txt # Rename file
sftp> mkdir newfolder       # Create directory
sftp> bye                   # Disconnect
```

#### FileZilla

```
Host: sftp://localhost
Port: 2222
Protocol: SFTP - SSH File Transfer Protocol
Logon Type: Normal
User: admin
Password: admin123
```

#### WinSCP

```
File protocol: SFTP
Host name: localhost
Port number: 2222
User name: admin
Password: admin123
```

### Uploading Files

```bash
# Single file
sftp> put document.pdf
Uploading document.pdf to /admin/document.pdf
document.pdf                    100%  1024KB   1.0MB/s   00:01

# Multiple files
sftp> mput *.pdf
Uploading file1.pdf to /admin/file1.pdf
Uploading file2.pdf to /admin/file2.pdf

# With progress
sftp> put largefile.zip
Uploading largefile.zip to /admin/largefile.zip
largefile.zip                   25%   250MB   10.0MB/s   00:75 ETA
```

Server logs:
```
[SFTP-OPEN] admin opened: document.pdf (0 B)
[SFTP-WRITE] document.pdf: 10.0 MB uploaded
[SFTP-WRITE] document.pdf: 20.0 MB uploaded
[SFTP-CLOSE] document.pdf closed (total: 0 B)
```

### Downloading Files

```bash
# Single file
sftp> get document.pdf
Fetching /admin/document.pdf to document.pdf
document.pdf                    100%  1024KB   1.0MB/s   00:01

# Multiple files
sftp> mget *.pdf
```

Server logs:
```
[SFTP-OPEN] admin opened: document.pdf (1.0 MB)
[SFTP-READ] document.pdf: 512 KB / 1.0 MB (50%)
[SFTP-READ] document.pdf: End of file reached (download complete)
[SFTP-CLOSE] document.pdf closed (total: 1.0 MB)
```

### File Management

```bash
# Rename
sftp> rename oldname.txt newname.txt
```

Server logs:
```
[SFTP-MOVE] admin moved: oldname.txt -> newname.txt
```

```bash
# Delete
sftp> rm unwanted.txt
```

Server logs:
```
[SFTP-DELETE] admin deleted: unwanted.txt
```

### Programmatic Access (Java)

```java
import com.jcraft.jsch.*;

public class SFTPClient {
    public static void main(String[] args) throws Exception {
        JSch jsch = new JSch();
        Session session = jsch.getSession("admin", "localhost", 2222);
        session.setPassword("admin123");
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
        
        ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
        channel.connect();
        
        // Upload file
        channel.put("local.txt", "remote.txt");
        
        // Download file
        channel.get("remote.txt", "downloaded.txt");
        
        // List files
        Vector<ChannelSftp.LsEntry> files = channel.ls(".");
        for (ChannelSftp.LsEntry file : files) {
            System.out.println(file.getFilename());
        }
        
        channel.disconnect();
        session.disconnect();
    }
}
```

---

## Performance Considerations

### Memory Usage

**Per Open File**:
```
Memory = chunk_size (buffer) + chunk_size (cache) + overhead
```

Examples:
- 64KB chunks: ~130KB per file
- 256KB chunks: ~520KB per file

**Concurrent Transfers**:
```
Total Memory ≈ concurrent_files × chunk_size × 2
```

Example: 10 concurrent transfers with 64KB chunks:
```
10 × 64KB × 2 = 1.28 MB (plus JVM overhead)
```

### Disk I/O

**Write Operations**:
- Sequential writes (optimal for HDDs)
- Chunk size aligned with file system block size recommended
- SSD: Any chunk size performs well

**Read Operations**:
- Random access supported
- Only requested chunks decrypted (no full-file read)
- Caching reduces repeated decryption

### CPU Usage

**Encryption Overhead**:
- AES-256-GCM is hardware-accelerated on modern CPUs with AES-NI support
- Performance impact varies based on CPU capabilities
- Generally negligible for typical SFTP workloads
- Chunk-based architecture allows for future parallelization

**Authentication**:
- PBKDF2 with 100K iterations intentionally adds computational delay
- Designed to slow down brute force attempts
- Timing varies based on CPU performance

### Network Throughput

**Factors**:
1. SSH protocol overhead
2. Encryption/decryption processing
3. Network bandwidth (typically primary bottleneck)
4. Disk I/O (secondary consideration)

**Typical Performance Characteristics**:
```
Network bandwidth: Primary bottleneck for most deployments
SSD throughput: Generally exceeds network capabilities
HDD throughput: May bottleneck on sequential operations

Expected: Network bandwidth typically limits transfer speeds
```

### Optimization Tips

1. **Chunk Size Tuning**:
   ```
   - Small files (<1MB): 16-32KB chunks
   - Medium files (1-100MB): 64-128KB chunks  
   - Large files (>100MB): 256KB-1MB chunks
   ```

2. **File System**:
   ```
   - Use ext4 or XFS on Linux
   - Disable atime updates: mount with 'noatime'
   - Align chunk size with block size if possible
   ```

3. **JVM Tuning**:
   ```bash
   # Recommended JVM flags
   -Xms1G -Xmx4G           # Heap size
   -XX:+UseG1GC            # Garbage collector
   -XX:MaxGCPauseMillis=200 # GC pause target
   ```

4. **Concurrent Connections**:
   ```
   - Monitor memory usage
   - Limit concurrent transfers if memory-constrained
   - Calculate: max_connections = (available_memory / chunk_size / 2)
   ```

---

## Security Considerations

### ⚠️ Educational Implementation Notice

This is a demonstration implementation for educational and testing purposes. The following security items are intentionally simplified and **MUST** be addressed before any production deployment.

### Critical Security Notes

1. **Master Key Management** (DEVELOPMENT/TESTING ONLY - CRITICAL FOR PRODUCTION):
   ```java
   // CURRENT IMPLEMENTATION (EDUCATIONAL/DEVELOPMENT ONLY):
   byte[] masterKeyBytes = Arrays.copyOf(
       "your-plaintext-password-here".getBytes(...), 32);
   
   // ⚠️ THIS IS NOT SECURE FOR PRODUCTION ⚠️
   
   // PRODUCTION REQUIREMENTS:
   // - Load from KMS (AWS KMS, Azure Key Vault, HashiCorp Vault)
   // - Use environment variables (minimum)
   // - Implement key rotation
   // - Add salt and proper key derivation
   // - Never hardcode credentials
   ```

2. **Keyset Storage**:
   - Current: Encrypted with master key
   - Recommended: Store in KMS or secure vault
   - Backup: Keep encrypted backups in separate location
   - Rotation: Implement regular key rotation policy

3. **User Authentication** (EDUCATIONAL IMPLEMENTATION):
   - Current: In-memory, PBKDF2-hashed (for testing/development)
   - Default credentials provided for demonstration purposes only
   - Production requirements:
     - Database with encrypted storage
     - LDAP/Active Directory integration
     - Multi-factor authentication (MFA)
     - Account lockout after failed attempts
     - No default credentials

4. **Network Security**:
   - Use firewall to restrict port 2222 access
   - Consider VPN or IP whitelisting
   - Monitor for brute force attempts
   - Implement rate limiting

5. **File System Permissions**:
   ```bash
   # Recommended permissions
   chmod 700 /data/sftp-storage      # Owner only
   chmod 600 /secure/keys/keyset.json # Owner read/write only
   chmod 600 /secure/keys/hostkey.ser # Owner read/write only
   ```

### Attack Scenarios & Mitigations

#### 1. Unauthorized Disk Access

**Scenario**: Attacker gains physical access to server disk

**Mitigation**:
- All files encrypted with AES-256-GCM
- Keyset encrypted with master key
- Master key stored in KMS (production)
- Result: Attacker cannot decrypt files without master key

#### 2. Chunk Manipulation

**Scenario**: Attacker modifies encrypted chunks on disk

**Mitigation**:
- Each chunk has GCM authentication tag
- Associated data includes filename and chunk index
- Tampering detected during decryption
- Result: Modified chunks rejected, read fails

#### 3. Chunk Reordering

**Scenario**: Attacker swaps chunk N with chunk M

**Mitigation**:
- Associated data: `"filename:chunk:N"`
- Decryption with wrong AAD fails
- Result: Reordered chunks detected and rejected

#### 4. Cross-File Attack

**Scenario**: Attacker copies chunk from file A to file B

**Mitigation**:
- Associated data includes filename
- Decryption requires matching filename
- Result: Cross-file chunks rejected

#### 5. Brute Force Authentication

**Scenario**: Attacker attempts password guessing

**Mitigation**:
- PBKDF2 with 100K iterations (~50-100ms per attempt)
- Constant-time comparison
- Dummy hash for invalid usernames
- Recommended: Add account lockout and rate limiting

#### 6. Timing Attacks

**Scenario**: Attacker measures authentication timing to enumerate users

**Mitigation**:
- Constant-time password comparison
- Dummy hash performed for non-existent users
- Same code path for success/failure
- Result: No timing difference between valid/invalid users

### Compliance Considerations

#### GDPR (General Data Protection Regulation)

- **Encryption at Rest**: Satisfied by AES-256-GCM
- **Right to Erasure**: Support by securely deleting encrypted files
- **Data Portability**: Users can download their files
- **Audit Logs**: Implement logging of all file access

#### HIPAA (Health Insurance Portability and Accountability Act)

- **Encryption**: AES-256 satisfies encryption requirements
- **Access Controls**: Per-user directories and authentication
- **Audit Trails**: Event listener provides basic audit logging
- **Recommended**: Add comprehensive audit logging for PHI

#### PCI DSS (Payment Card Industry Data Security Standard)

- **Encryption**: Requirement 3.4 satisfied
- **Access Control**: Requirement 7 (per-user access)
- **Audit Logging**: Requirement 10 (needs enhancement)
- **Key Management**: Requirement 3.6 (needs KMS integration)

### Security Checklist for Production

- [ ] Replace hardcoded master key with KMS
- [ ] Implement key rotation policy
- [ ] Move user authentication to database/LDAP
- [ ] Add multi-factor authentication (MFA)
- [ ] Implement comprehensive audit logging
- [ ] Set up file system permissions correctly
- [ ] Configure firewall rules
- [ ] Enable rate limiting on authentication
- [ ] Set up encrypted backups of keyset
- [ ] Document incident response procedures
- [ ] Conduct security audit/penetration test
- [ ] Set up monitoring and alerting
- [ ] Implement account lockout policy
- [ ] Configure log retention and analysis

---

## Troubleshooting

### Common Issues

#### 1. Server Won't Start - Port Already in Use

**Error**:
```
java.net.BindException: Address already in use
```

**Solution**:
```bash
# Find process using port 2222
lsof -i :2222
netstat -tulpn | grep 2222

# Kill process or use different port
java -Dsftp.port=2223 -jar sftp-server.jar
```

#### 2. Connection Refused

**Error** (client):
```
ssh: connect to host localhost port 2222: Connection refused
```

**Solutions**:
1. Check server is running
2. Check firewall rules:
   ```bash
   # Allow port 2222
   sudo ufw allow 2222/tcp
   sudo firewall-cmd --add-port=2222/tcp --permanent
   ```
3. Verify correct port and hostname

#### 3. Authentication Failed

**Error**:
```
Permission denied (publickey,password).
```

**Solutions**:
1. Verify credentials (default: admin/admin123)
2. Check server logs for auth attempts
3. Verify user exists:
   ```java
   UserAuthenticationService.addUser("username", "password");
   ```

#### 4. File Upload Fails Midway

**Error**:
```
Write failed: Broken pipe
```

**Possible Causes**:
1. Disk full
2. Out of memory
3. Network interruption

**Solutions**:
```bash
# Check disk space
df -h /data/sftp-storage

# Check memory
free -h
top

# Increase memory if needed
java -Xmx4G -jar sftp-server.jar
```

#### 5. Encryption/Decryption Errors

**Error**:
```
GeneralSecurityException: decryption failed
```

**Causes**:
1. File corrupted on disk
2. Wrong encryption key
3. File modified outside SFTP

**Solutions**:
1. Verify keyset.json not modified
2. Check file integrity:
   ```bash
   # File should start with "CENC"
   xxd -l 4 /data/sftp-storage/admin/file.pdf
   ```
3. Restore from backup if corrupted

#### 6. High Memory Usage

**Symptom**:
```
Java heap space OutOfMemoryError
```

**Solutions**:
1. Reduce chunk size:
   ```bash
   java -Dsftp.chunk.size=32768 -jar sftp-server.jar
   ```

2. Increase heap:
   ```bash
   java -Xmx4G -jar sftp-server.jar
   ```

3. Limit concurrent connections (implement connection pooling)

#### 7. Slow Performance

**Symptoms**:
- Slow uploads/downloads
- High CPU usage

**Solutions**:
1. Check disk I/O:
   ```bash
   iostat -x 1 10
   ```

2. Check CPU:
   ```bash
   top
   ```

3. Optimize chunk size based on workload

4. Use SSD instead of HDD

5. Check network bandwidth:
   ```bash
   iperf3 -s  # On server
   iperf3 -c server_ip  # On client
   ```

### Debug Logging

Enable detailed logging:

```bash
# Set logging level
java -Dorg.apache.sshd.common.util.logging=DEBUG \
     -jar sftp-server.jar
```

Create `logback.xml`:
```xml
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="DEBUG">
        <appender-ref ref="STDOUT" />
    </root>
</configuration>
```

### Monitoring

**Key Metrics to Monitor**:

1. **System Metrics**:
   - CPU usage
   - Memory usage
   - Disk I/O
   - Network throughput

2. **Application Metrics**:
   - Active connections
   - Authentication failures
   - File transfer rates
   - Error rates

3. **Security Metrics**:
   - Failed login attempts
   - Unusual file access patterns
   - Encryption/decryption errors

**Example Monitoring Script**:

```bash
#!/bin/bash

# Monitor SFTP server health
while true; do
    # Check if server is running
    if ! pgrep -f "ChunkedEncryptedSftpServer" > /dev/null; then
        echo "ALERT: SFTP server is down!" | mail -s "SFTP Alert" admin@example.com
    fi
    
    # Check disk space
    DISK_USAGE=$(df -h /data/sftp-storage | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $DISK_USAGE -gt 90 ]; then
        echo "ALERT: Disk usage at ${DISK_USAGE}%" | mail -s "Disk Alert" admin@example.com
    fi
    
    # Check memory
    MEM_USAGE=$(free | awk 'NR==2 {print $3/$2 * 100.0}')
    if (( $(echo "$MEM_USAGE > 90" | bc -l) )); then
        echo "ALERT: Memory usage at ${MEM_USAGE}%" | mail -s "Memory Alert" admin@example.com
    fi
    
    sleep 300  # Check every 5 minutes
done
```

---

## API Reference

### ChunkedEncryptionService

```java
public class ChunkedEncryptionService {
    /**
     * Constructor with default chunk size (64KB)
     */
    public ChunkedEncryptionService(Path keysetPath) 
        throws GeneralSecurityException, IOException
    
    /**
     * Constructor with custom chunk size
     */
    public ChunkedEncryptionService(Path keysetPath, int chunkSize) 
        throws GeneralSecurityException, IOException
    
    /**
     * Encrypt plaintext stream and write to output
     */
    public void encryptStream(byte[] plaintext, String filename, OutputStream output)
        throws GeneralSecurityException, IOException
    
    /**
     * Decrypt stream from input and return plaintext
     */
    public byte[] decryptStream(InputStream input, String filename)
        throws GeneralSecurityException, IOException
    
    /**
     * Get file header without decrypting content
     */
    public FileHeader getFileHeader(InputStream input) throws IOException
    
    /**
     * Decrypt specific chunk by index (for random access)
     */
    public byte[] decryptChunkByIndex(
        RandomAccessFile input, 
        String filename, 
        int chunkIndex
    ) throws IOException, GeneralSecurityException
    
    /**
     * Encrypt single chunk
     */
    public byte[] encryptChunk(byte[] chunk, String filename, int chunkIndex)
        throws GeneralSecurityException
    
    /**
     * Decrypt single chunk
     */
    public byte[] decryptChunk(byte[] encryptedChunk, String filename, int chunkIndex)
        throws GeneralSecurityException
    
    /**
     * Get configured chunk size
     */
    public int getChunkSize()
    
    /**
     * File header information
     */
    public static class FileHeader {
        public final short version;
        public final int chunkSize;
        public final long originalSize;
        
        public int getTotalChunks()
    }
}
```

### UserAuthenticationService

```java
public class UserAuthenticationService {
    /**
     * Authenticate user with username and password
     * Returns true if credentials valid, false otherwise
     */
    public static boolean authenticate(String username, String password)
    
    /**
     * Add new user with password
     * Minimum password length: 8 characters
     */
    public static void addUser(String username, String password) throws Exception
}
```

### ChunkedEncryptedSftpServer

```java
public class ChunkedEncryptedSftpServer {
    /**
     * Create SFTP server with encryption
     */
    public ChunkedEncryptedSftpServer(
        int port,
        Path storageRoot,
        Path keysetPath,
        boolean useEncExtension,
        int chunkSize
    ) throws Exception
    
    /**
     * Start the SFTP server
     */
    public void start() throws IOException
    
    /**
     * Stop the SFTP server
     */
    public void stop() throws IOException
    
    /**
     * Check if server is running
     */
    public boolean isStarted()
    
    /**
     * Get server port
     */
    public int getPort()
}
```

---

## Appendix

### File Format Example

Hex dump of encrypted file header:

```
00000000: 43 45 4e 43 00 01 00 01  00 00 28 9a 00 00 00 00  |CENC......(.....|
00000010: 00 00 01 a4 f3 8e 2d 1c  9a 45 b2 73 c4 91 e8 2f  |......-..E.s.../|
00000020: 00 00 10 50 18 a3 f1 2c  ...                      |...P...,        |
          ^magic ^ver ^chunk    ^original_size  ^padding
```

Breakdown:
- `43 45 4e 43`: "CENC" magic bytes
- `00 01`: Version 1
- `00 01 00 00`: Chunk size 65536 (64KB)
- `00 00 00 00 00 00 01 a4`: Original size 420 bytes
- Remaining: Random padding

### Chunk Encryption Example

```
Plaintext chunk:
  Data: "Hello, World!" (13 bytes)
  Filename: "test.txt"
  Chunk index: 0

Associated Data (AAD):
  "test.txt:chunk:0"

Encryption:
  Algorithm: AES-256-GCM
  Input: plaintext + AAD
  Output: ciphertext (13 bytes) + tag (16 bytes) = 29 bytes

Encrypted chunk structure:
  [00 00 00 1D]  # Chunk size: 29 bytes
  [<29 bytes of encrypted data including 16-byte tag>]
```

### Performance Benchmarks

Performance will vary based on your specific hardware configuration:

**Key Factors**:
- CPU performance and AES-NI support
- RAM availability
- Disk I/O (SSD vs HDD)
- Network bandwidth

**Expected Characteristics**:
- Network bandwidth is typically the primary bottleneck
- AES-256-GCM is hardware-accelerated on modern CPUs (minimal overhead)
- Chunk size has minimal impact on throughput for most workloads
- Larger chunks may slightly reduce CPU usage

**Recommendation**: Benchmark on your specific hardware to determine optimal chunk size and configuration.

### License

**Educational and Development Use**

This implementation is provided for educational, development, and testing purposes. It demonstrates encryption-at-rest concepts and is not intended for production use without significant security enhancements.

**Dependencies Licenses**:
- Apache MINA SSHD: Apache License 2.0
- Google Tink: Apache License 2.0
- SLF4J: MIT License
- Logback: Eclipse Public License 1.0 / LGPL 2.1

**Disclaimer**: This software is provided "as-is" without warranty of any kind. See repository LICENSE file for details.

### Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

### Support

For issues and questions:
- GitHub Issues: [https://github.com/PortaSFTPServer/MinaSSHDDataAtRestEncryptionSample/issues](https://github.com/PortaSFTPServer/MinaSSHDDataAtRestEncryptionSample/issues)
- Documentation: This README
- Security Issues: Report privately via GitHub Security Advisories

### Changelog

**Version 1.0.0** (Current)
- Initial release
- Apache MINA SSHD 2.17.1 support
- Google Tink 1.20.0 integration
- Chunk-based AES-256-GCM encryption
- Streaming architecture with random access
- PBKDF2 user authentication
- Event-based logging

**Planned Features**:
- Database-backed user authentication
- LDAP/Active Directory integration
- Multi-factor authentication (MFA)
- Key rotation automation
- Comprehensive audit logging
- Web-based administration panel
- Metrics and monitoring dashboard
- Public key authentication
- SFTP command logging
- File versioning support

---

## Quick Reference Card

### Server Commands

```bash
# Start server (default config)
java -jar sftp-server.jar

# Start with custom port
java -Dsftp.port=3333 -jar sftp-server.jar

# Start with custom storage
java -Dsftp.storage=/data/sftp -jar sftp-server.jar

# Start with larger chunks (1MB)
java -Dsftp.chunk.size=1048576 -jar sftp-server.jar

# Enable .enc extension mode
java -Dsftp.use.enc.extension=true -jar sftp-server.jar
```

### SFTP Client Commands

```bash
# Connect
sftp -P 2222 admin@localhost

# Upload
put local.txt
mput *.pdf

# Download
get remote.txt
mget *.pdf

# Delete
rm file.txt

# Rename/Move
rename old.txt new.txt

# List
ls
ls -la

# Change directory
cd folder
pwd

# Create directory
mkdir newfolder

# Disconnect
bye
```

### Default Configuration

```
Port: 2222
Storage: ./sftp-storage
Keyset: ./keyset.json
Chunk Size: 64 KB
Extension Mode: Disabled
Users: admin/admin123, testuser/password123
```

### File Locations

```
./keyset.json           # Encryption keyset (encrypted)
./hostkey.ser           # SSH host key
./sftp-storage/         # Storage root
./sftp-storage/admin/   # Admin user files
./sftp-storage/testuser/# Test user files
```

---

**End of Documentation**
