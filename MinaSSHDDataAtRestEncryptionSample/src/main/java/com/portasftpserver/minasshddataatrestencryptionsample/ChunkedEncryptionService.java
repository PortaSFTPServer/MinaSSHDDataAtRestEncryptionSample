package com.portasftpserver.minasshddataatrestencryptionsample;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.subtle.AesGcmJce;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Chunked encryption service with streaming support for large files.
 *
 * File format: [HEADER: 16 bytes] [CHUNK_0: encrypted] [CHUNK_1: encrypted] ...
 *
 * Header format (16 bytes): - Magic bytes (4): "CENC" - Version (2): 0x0001 -
 * Chunk size (4): default 64KB - Original file size (8): for validation -
 * Reserved (6): future use
 *
 * Each chunk is independently encrypted with AES-256-GCM using: - Associated
 * data: filename + chunk_index - This allows random access while maintaining
 * authentication
 */
public class ChunkedEncryptionService {

    private static final byte[] MAGIC = "CENC".getBytes();
    private static final short VERSION = 1;
    private static final int HEADER_SIZE = 32; // Increased for better alignment
    private static final int DEFAULT_CHUNK_SIZE = 64 * 1024; // 64KB chunks
    private static final int GCM_TAG_SIZE = 16; // AES-GCM authentication tag size

    private final Aead aead;
    private final int chunkSize;

    /**
     * Create encryption service with default chunk size (64KB)
     */
    public ChunkedEncryptionService(Path keysetPath) throws GeneralSecurityException, IOException {
        this(keysetPath, DEFAULT_CHUNK_SIZE);
    }

    /**
     * Create encryption service with custom chunk size
     *
     * @param keysetPath Path to encryption keyset
     * @param chunkSize Chunk size in bytes (must be > 0)
     */
    public ChunkedEncryptionService(Path keysetPath, int chunkSize) throws GeneralSecurityException, IOException {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be positive");
        }

        AeadConfig.register();
        KeysetHandle keysetHandle = loadOrCreateKeyset(keysetPath);
        this.aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        this.chunkSize = chunkSize;

        System.out.println("[CRYPTO] AES-256-GCM initialized (chunk size: " + chunkSize + " bytes)");
    }

    private KeysetHandle loadOrCreateKeyset(Path keysetPath) throws GeneralSecurityException, IOException {

        // this should be coming from your KMS as from param
        // i am lazy to add the connection here
        // password must be salted as well
        // password mus be decrypted for initialization
        byte[] masterKeyBytes = Arrays.copyOf(
                "your-plaintext-password-here".getBytes(StandardCharsets.UTF_8),
                32
        );

        Aead masterKeyAead = new AesGcmJce(masterKeyBytes);

        if (Files.exists(keysetPath)) {

            // 1. Read the encrypted JSON string from your storage
            String encryptedKeysetJson = new String(
                    Files.readAllBytes(Paths.get("keyset.json")),
                    StandardCharsets.UTF_8
            );
            // 2. Parse the encrypted keyset using your master key
           
            //return CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(in));

            return TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                    encryptedKeysetJson,
                    masterKeyAead,
                    new byte[0] // associatedData
            );

        } else {
            if (keysetPath.getParent() != null) {
                Files.createDirectories(keysetPath.getParent());
            }

            KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
            
            try (OutputStream out = Files.newOutputStream(keysetPath)) {

                // CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(out));
                String serializedKeyset = TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
                        handle, masterKeyAead,
                        new byte[0] // associatedData
                );

                out.write(serializedKeyset.getBytes(StandardCharsets.UTF_8));
            }

            System.out.println("[CRYPTO] New keyset created: " + keysetPath);

            return handle;
        }
    }

    /**
     * Encrypt plaintext in chunks and write to output stream
     *
     * @param plaintext Source plaintext data
     * @param filename Associated data (filename)
     * @param output Target output stream
     */
    public void encryptStream(byte[] plaintext, String filename, OutputStream output)
            throws GeneralSecurityException, IOException {

        long originalSize = plaintext.length;
        int totalChunks = (int) Math.ceil((double) plaintext.length / chunkSize);

        // Write header
        writeHeader(output, originalSize);

        // Encrypt and write chunks
        for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
            int offset = chunkIndex * chunkSize;
            int length = Math.min(chunkSize, plaintext.length - offset);

            byte[] chunk = Arrays.copyOfRange(plaintext, offset, offset + length);
            byte[] encryptedChunk = encryptChunk(chunk, filename, chunkIndex);

            // Write chunk size (4 bytes) then encrypted chunk
            writeInt(output, encryptedChunk.length);
            output.write(encryptedChunk);
        }
    }

    /**
     * Decrypt entire file from input stream
     *
     * @param input Encrypted input stream
     * @param filename Associated data (filename)
     * @return Decrypted plaintext
     */
    public byte[] decryptStream(InputStream input, String filename)
            throws GeneralSecurityException, IOException {

        // Read and validate header
        FileHeader header = readHeader(input);

        ByteArrayOutputStream result = new ByteArrayOutputStream((int) header.originalSize);
        int chunkIndex = 0;

        // Decrypt chunks
        while (true) {
            byte[] sizeBytes = new byte[4];
            int read = input.read(sizeBytes);
            if (read < 4) {
                break; // End of file
            }
            int encryptedChunkSize = bytesToInt(sizeBytes);
            if (encryptedChunkSize <= 0 || encryptedChunkSize > chunkSize + GCM_TAG_SIZE + 100) {
                throw new IOException("Invalid chunk size: " + encryptedChunkSize);
            }

            byte[] encryptedChunk = new byte[encryptedChunkSize];
            int totalRead = 0;
            while (totalRead < encryptedChunkSize) {
                int n = input.read(encryptedChunk, totalRead, encryptedChunkSize - totalRead);
                if (n < 0) {
                    throw new IOException("Unexpected EOF");
                }
                totalRead += n;
            }

            byte[] decryptedChunk = decryptChunk(encryptedChunk, filename, chunkIndex);
            result.write(decryptedChunk);
            chunkIndex++;
        }

        byte[] decrypted = result.toByteArray();
        if (decrypted.length != header.originalSize) {
            throw new IOException("Size mismatch: expected " + header.originalSize
                    + ", got " + decrypted.length);
        }

        return decrypted;
    }

    /**
     * Get file metadata without decrypting (reads only header)
     */
    public FileHeader getFileHeader(InputStream input) throws IOException {
        return readHeader(input);
    }

    /**
     * Decrypt specific chunk by index (for random access)
     *
     * @param input Encrypted file input stream (positioned at start)
     * @param filename Associated data
     * @param chunkIndex Chunk index to decrypt
     * @return Decrypted chunk data
     */
    public byte[] decryptChunkByIndex(RandomAccessFile input, String filename, int chunkIndex)
            throws GeneralSecurityException, IOException {

        // Read header to get chunk positions
        input.seek(0);
        byte[] headerBytes = new byte[HEADER_SIZE];
        int headerRead = input.read(headerBytes);
        if (headerRead < HEADER_SIZE) {
            throw new IOException("File too short: cannot read header (read " + headerRead + " bytes)");
        }

        FileHeader header = parseHeader(headerBytes);

        // Validate chunk index
        int totalChunks = header.getTotalChunks();
        if (chunkIndex < 0 || chunkIndex >= totalChunks) {
            throw new IOException("Invalid chunk index: " + chunkIndex
                    + " (file has " + totalChunks + " chunks)");
        }

        // Calculate position of target chunk by iterating through chunk sizes
        long position = HEADER_SIZE;
        for (int i = 0; i < chunkIndex; i++) {
            input.seek(position);

            // Read chunk size
            byte[] sizeBytes = new byte[4];
            int read = input.read(sizeBytes);
            if (read < 4) {
                throw new IOException("Unexpected EOF while reading chunk " + i + " size");
            }

            int chunkSize = bytesToInt(sizeBytes);
            if (chunkSize <= 0 || chunkSize > chunkSize + GCM_TAG_SIZE + 1000) {
                throw new IOException("Invalid chunk size at index " + i + ": " + chunkSize);
            }

            position += 4 + chunkSize;
        }

        // Read target chunk
        input.seek(position);

        // Read encrypted chunk size
        byte[] sizeBytes = new byte[4];
        int sizeRead = input.read(sizeBytes);
        if (sizeRead < 4) {
            throw new IOException("Unexpected EOF while reading chunk " + chunkIndex
                    + " size at position " + position);
        }

        int encryptedChunkSize = bytesToInt(sizeBytes);

        // Validate chunk size
        if (encryptedChunkSize <= 0) {
            throw new IOException("Invalid encrypted chunk size for chunk " + chunkIndex
                    + ": " + encryptedChunkSize);
        }

        if (encryptedChunkSize > chunkSize + GCM_TAG_SIZE + 1000) {
            throw new IOException("Encrypted chunk size too large for chunk " + chunkIndex
                    + ": " + encryptedChunkSize + " (max expected: "
                    + (chunkSize + GCM_TAG_SIZE) + ")");
        }

        // Check if we have enough data in file
        long fileLength = input.length();
        long requiredLength = position + 4 + encryptedChunkSize;
        if (requiredLength > fileLength) {
            throw new IOException("File truncated: chunk " + chunkIndex
                    + " requires " + requiredLength + " bytes but file is only "
                    + fileLength + " bytes");
        }

        // Read encrypted chunk data
        byte[] encryptedChunk = new byte[encryptedChunkSize];
        int totalRead = 0;
        while (totalRead < encryptedChunkSize) {
            int n = input.read(encryptedChunk, totalRead, encryptedChunkSize - totalRead);
            if (n < 0) {
                throw new IOException("Unexpected EOF while reading chunk " + chunkIndex
                        + " data (read " + totalRead + " of " + encryptedChunkSize + ")");
            }
            totalRead += n;
        }

        // Decrypt chunk
        byte[] decrypted = decryptChunk(encryptedChunk, filename, chunkIndex);

        // Validate decrypted size for last chunk
        if (chunkIndex == totalChunks - 1) {
            int expectedLastChunkSize = (int) (header.originalSize % chunkSize);
            if (expectedLastChunkSize == 0) {
                expectedLastChunkSize = chunkSize;
            }

            if (decrypted.length != expectedLastChunkSize) {
                System.err.println("[WARN] Last chunk size mismatch: expected="
                        + expectedLastChunkSize + " actual=" + decrypted.length);
            }
        }

        return decrypted;
    }

    /**
     * Encrypt a single chunk (public for channel use)
     */
    public byte[] encryptChunk(byte[] chunk, String filename, int chunkIndex)
            throws GeneralSecurityException {
        String associatedData = filename + ":chunk:" + chunkIndex;
        return aead.encrypt(chunk, associatedData.getBytes());
    }

    /**
     * Decrypt a single chunk (public for channel use)
     */
    public byte[] decryptChunk(byte[] encryptedChunk, String filename, int chunkIndex)
            throws GeneralSecurityException {
        String associatedData = filename + ":chunk:" + chunkIndex;
        return aead.decrypt(encryptedChunk, associatedData.getBytes());
    }

    /**
     * Write file header
     */
    private void writeHeader(OutputStream output, long originalSize) throws IOException {
        ByteArrayOutputStream header = new ByteArrayOutputStream(HEADER_SIZE);

        header.write(MAGIC);                           // 4 bytes: magic
        writeShort(header, VERSION);                   // 2 bytes: version
        writeInt(header, chunkSize);                   // 4 bytes: chunk size
        writeLong(header, originalSize);               // 8 bytes: original size

        // Pad to HEADER_SIZE
        byte[] padding = new byte[HEADER_SIZE - header.size()];
        new SecureRandom().nextBytes(padding);
        header.write(padding);

        output.write(header.toByteArray());
    }

    /**
     * Read and validate file header
     */
    private FileHeader readHeader(InputStream input) throws IOException {
        byte[] headerBytes = new byte[HEADER_SIZE];
        int read = input.read(headerBytes);
        if (read < HEADER_SIZE) {
            throw new IOException("Invalid encrypted file: header too short");
        }

        return parseHeader(headerBytes);
    }

    private FileHeader parseHeader(byte[] headerBytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(headerBytes);

        // Validate magic
        byte[] magic = new byte[4];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid encrypted file: bad magic bytes");
        }

        // Read header fields
        short version = buffer.getShort();
        if (version != VERSION) {
            throw new IOException("Unsupported version: " + version);
        }

        int storedChunkSize = buffer.getInt();
        long originalSize = buffer.getLong();

        return new FileHeader(version, storedChunkSize, originalSize);
    }

    // Helper methods for byte conversion
    private void writeShort(OutputStream out, short value) throws IOException {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private void writeInt(OutputStream out, int value) throws IOException {
        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private void writeLong(OutputStream out, long value) throws IOException {
        out.write((int) (value >> 56) & 0xFF);
        out.write((int) (value >> 48) & 0xFF);
        out.write((int) (value >> 40) & 0xFF);
        out.write((int) (value >> 32) & 0xFF);
        out.write((int) (value >> 24) & 0xFF);
        out.write((int) (value >> 16) & 0xFF);
        out.write((int) (value >> 8) & 0xFF);
        out.write((int) value & 0xFF);
    }

    private int bytesToInt(byte[] bytes) {
        if (bytes == null || bytes.length < 4) {
            throw new IllegalArgumentException("Need at least 4 bytes to convert to int");
        }
        return ((bytes[0] & 0xFF) << 24)
                | ((bytes[1] & 0xFF) << 16)
                | ((bytes[2] & 0xFF) << 8)
                | (bytes[3] & 0xFF);
    }

    public int getChunkSize() {
        return chunkSize;
    }

    /**
     * File header information
     */
    public static class FileHeader {

        public final short version;
        public final int chunkSize;
        public final long originalSize;

        public FileHeader(short version, int chunkSize, long originalSize) {
            this.version = version;
            this.chunkSize = chunkSize;
            this.originalSize = originalSize;
        }

        public int getTotalChunks() {
            return (int) Math.ceil((double) originalSize / chunkSize);
        }
    }
}
