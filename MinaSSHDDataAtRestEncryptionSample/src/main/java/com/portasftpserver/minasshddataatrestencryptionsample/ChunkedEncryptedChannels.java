package com.portasftpserver.minasshddataatrestencryptionsample;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Chunked encryption channels with streaming and random access support.
 * Compatible with Apache MINA SSHD 2.16.0 SeekableByteChannel interface.
 * 
 * Features:
 * - Streaming encryption/decryption (no full file in memory)
 * - Random access support (seeking to any position)
 * - Chunk-based processing for large files
 * - Transparent encryption/decryption
 */
public class ChunkedEncryptedChannels {
    
    /**
     * Read channel with chunk-based decryption and random access support.
     * 
     * Only decrypts chunks as needed, supporting efficient seeking.
     */
    public static class ChunkedReadChannel implements SeekableByteChannel {
        private final RandomAccessFile encryptedFile;
        private final String filename;
        private final ChunkedEncryptionService crypto;
        private final ChunkedEncryptionService.FileHeader header;
        
        // Cache for current chunk
        private int currentChunkIndex = -1;
        private byte[] currentChunkData = null;
        
        // Position tracking
        private long position = 0;
        private boolean open = true;
        
        public ChunkedReadChannel(Path encryptedPath, String filename, ChunkedEncryptionService crypto) 
                throws IOException {
            this.filename = filename;
            this.crypto = crypto;
            this.encryptedFile = new RandomAccessFile(encryptedPath.toFile(), "r");
            
            try {
                // Read header to get file metadata
                this.header = crypto.getFileHeader(new FileInputStream(encryptedFile.getFD()));
                System.out.println("[READ-CHUNKED] Opened: " + filename + 
                                 " (size: " + header.originalSize + " bytes, " + 
                                 header.getTotalChunks() + " chunks)");
            } catch (Exception e) {
                encryptedFile.close();
                throw new IOException("Failed to read encrypted file header", e);
            }
        }
        
        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (!open) throw new IOException("Channel closed");
            
            // EOF check: return -1 immediately if at or past end
            if (position >= header.originalSize) {
                System.out.println("[READ-EOF] Position " + position + " >= size " + header.originalSize);
                return -1;
            }
            
            // If buffer has no space, this is technically valid but pointless
            if (dst.remaining() == 0) {
                System.out.println("[READ-WARN] Zero-length read requested at position " + position);
                return 0; // Can't read anything into zero-space buffer
            }
            
            int totalRead = 0;
            int remaining = dst.remaining();
            
            while (remaining > 0 && position < header.originalSize) {
                // Calculate which chunk we need
                int chunkIndex = (int) (position / header.chunkSize);
                int offsetInChunk = (int) (position % header.chunkSize);
                
                // Validate chunk index
                if (chunkIndex >= header.getTotalChunks()) {
                    System.err.println("[READ-ERROR] Chunk index " + chunkIndex + 
                                     " >= total chunks " + header.getTotalChunks());
                    break; // EOF reached
                }
                
                // Load chunk if not cached
                if (chunkIndex != currentChunkIndex) {
                    try {
                        loadChunk(chunkIndex);
                    } catch (IOException e) {
                        if (totalRead > 0) {
                            // Already read some data, return what we have
                            System.out.println("[READ-PARTIAL] Returning " + totalRead + 
                                             " bytes before error");
                            return totalRead;
                        }
                        throw e;
                    }
                }
                
                // Validate chunk was loaded
                if (currentChunkData == null) {
                    System.err.println("[READ-ERROR] Failed to load chunk " + chunkIndex);
                    if (totalRead > 0) return totalRead;
                    throw new IOException("Failed to load chunk " + chunkIndex);
                }
                
                // Calculate how much we can read from current chunk
                int availableInChunk = currentChunkData.length - offsetInChunk;
                
                // Don't read past end of file
                long remainingInFile = header.originalSize - position;
                
                // Read the minimum of: what's requested, what's in chunk, what's left in file
                int toRead = (int) Math.min(Math.min(remaining, availableInChunk), remainingInFile);
                
                if (toRead <= 0) {
                    // Safety check - should not happen if logic above is correct
                    System.err.println("[READ-WARN] Calculated toRead=" + toRead + 
                                     " (remaining=" + remaining + 
                                     ", availInChunk=" + availableInChunk + 
                                     ", remainInFile=" + remainingInFile + ")");
                    break;
                }
                
                System.out.println("[READ-DATA] Chunk " + chunkIndex + 
                                 " offset=" + offsetInChunk + 
                                 " toRead=" + toRead + 
                                 " pos=" + position + "/" + header.originalSize);
                
                dst.put(currentChunkData, offsetInChunk, toRead);
                
                position += toRead;
                totalRead += toRead;
                remaining -= toRead;
            }
            
            // CRITICAL: Never return 0 when we're at EOF
            // SSHD interprets 0 as "try again" but -1 as "end of stream"
            if (totalRead == 0 && position >= header.originalSize) {
                System.out.println("[READ-EOF] No data read, at EOF, returning -1");
                return -1;
            }
            
            if (totalRead == 0 && position < header.originalSize) {
                // This should never happen - indicates a bug
                System.err.println("[READ-BUG] No data read but not at EOF! " +
                                 "pos=" + position + " size=" + header.originalSize);
                throw new IOException("Failed to read any data (position=" + position + 
                                    ", size=" + header.originalSize + ")");
            }
            
            System.out.println("[READ-SUCCESS] Read " + totalRead + " bytes, new position: " + position);
            return totalRead;
        }
        
        /**
         * Load and decrypt a specific chunk with enhanced error handling
         */
        private void loadChunk(int chunkIndex) throws IOException {
            try {
                // Validate chunk index
                if (chunkIndex < 0 || chunkIndex >= header.getTotalChunks()) {
                    throw new IOException("Invalid chunk index: " + chunkIndex + 
                                        " (total: " + header.getTotalChunks() + ")");
                }
                
                // Clear old chunk data
                if (currentChunkData != null) {
                    Arrays.fill(currentChunkData, (byte) 0);
                }
                
                currentChunkData = crypto.decryptChunkByIndex(encryptedFile, filename, chunkIndex);
                currentChunkIndex = chunkIndex;
                
                // Validate chunk data
                if (currentChunkData == null) {
                    throw new IOException("Decryption returned null for chunk " + chunkIndex);
                }
                
                // Validate chunk size (last chunk may be smaller)
                int expectedSize;
                if (chunkIndex == header.getTotalChunks() - 1) {
                    // Last chunk: size = remaining bytes
                    expectedSize = (int) (header.originalSize - (chunkIndex * header.chunkSize));
                } else {
                    // Regular chunk
                    expectedSize = header.chunkSize;
                }
                
                if (currentChunkData.length != expectedSize) {
                    System.err.println("[WARN] Chunk " + chunkIndex + " size mismatch: " +
                                     "expected=" + expectedSize + " actual=" + currentChunkData.length);
                    // Continue anyway - the data might still be valid
                }
                
                System.out.println("[READ-CHUNKED] Decrypted chunk " + chunkIndex + 
                                 " (" + currentChunkData.length + " bytes)");
                
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to decrypt chunk " + chunkIndex + ": " + e.getMessage(), e);
            } catch (Exception e) {
                throw new IOException("Error loading chunk " + chunkIndex + ": " + e.getMessage(), e);
            }
        }
        
        @Override
        public int write(ByteBuffer src) throws IOException {
            throw new UnsupportedOperationException("Read-only channel");
        }
        
        @Override
        public long position() {
            return position;
        }
        
        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            if (!open) throw new IOException("Channel closed");
            if (newPosition < 0) {
                throw new IllegalArgumentException("Negative position: " + newPosition);
            }
            
            // Allow seeking past EOF (POSIX behavior)
            // Reads will return -1, but position is set
            this.position = newPosition;
            
            System.out.println("[SEEK] Position: " + position + 
                             " (size: " + header.originalSize + 
                             ", chunk: " + (position / header.chunkSize) + ")");
            return this;
        }
        
        @Override
        public long size() {
            return header.originalSize;
        }
        
        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            throw new UnsupportedOperationException("Read-only channel");
        }
        
        @Override
        public boolean isOpen() {
            return open;
        }
        
        @Override
        public void close() throws IOException {
            if (open) {
                if (currentChunkData != null) {
                    Arrays.fill(currentChunkData, (byte) 0);
                    currentChunkData = null;
                }
                encryptedFile.close();
                open = false;
                System.out.println("[READ-CHUNKED] Closed: " + filename);
            }
        }
    }
    
    /**
     * Write channel with chunk-based encryption.
     * 
     * Buffers data in memory up to chunk size, then encrypts and writes to disk.
     * On close, encrypts any remaining data and finalizes the file.
     */
    public static class ChunkedWriteChannel implements SeekableByteChannel {
        private final Path targetFile;
        private final String filename;
        private final ChunkedEncryptionService crypto;
        
        // Buffering
        private final ByteArrayOutputStream buffer;
        private final OutputStream fileOutput;
        private final int chunkSize;
        
        // State tracking
        private boolean headerWritten = false;
        private int chunkIndex = 0;
        private long totalBytesWritten = 0;
        private boolean open = true;
        
        public ChunkedWriteChannel(Path targetFile, String filename, ChunkedEncryptionService crypto) 
                throws IOException {
            this.targetFile = targetFile;
            this.filename = filename;
            this.crypto = crypto;
            this.chunkSize = crypto.getChunkSize();
            this.buffer = new ByteArrayOutputStream(chunkSize);
            
            // Ensure parent directory exists
            if (targetFile.getParent() != null) {
                Files.createDirectories(targetFile.getParent());
            }
            
            // Open file for writing
            this.fileOutput = new BufferedOutputStream(Files.newOutputStream(targetFile));
            
            System.out.println("[WRITE-CHUNKED] Created: " + filename + 
                             " (chunk size: " + chunkSize + " bytes)");
        }
        
        @Override
        public int write(ByteBuffer src) throws IOException {
            if (!open) throw new IOException("Channel closed");
            
            int totalWritten = 0;
            
            while (src.hasRemaining()) {
                // Calculate how much we can buffer
                int spaceInBuffer = chunkSize - buffer.size();
                int toWrite = Math.min(src.remaining(), spaceInBuffer);
                
                // Write to buffer
                byte[] data = new byte[toWrite];
                src.get(data);
                buffer.write(data);
                totalWritten += toWrite;
                totalBytesWritten += toWrite;
                
                // If buffer is full, encrypt and flush
                if (buffer.size() >= chunkSize) {
                    flushChunk(false);
                }
            }
            
            return totalWritten;
        }
        
        /**
         * Flush current buffer as an encrypted chunk
         */
        private void flushChunk(boolean isFinal) throws IOException {
            if (buffer.size() == 0 && !isFinal) {
                return; // Nothing to flush
            }
            
            // Write header on first chunk
            if (!headerWritten) {
                writeHeader();
                headerWritten = true;
            }
            
            try {
                byte[] plaintext = buffer.toByteArray();
                
                if (plaintext.length > 0) {
                    // Encrypt chunk
                    String associatedData = filename + ":chunk:" + chunkIndex;
                    byte[] encrypted = encryptChunkData(plaintext, associatedData);
                    
                    // Write chunk size + encrypted data
                    writeInt(fileOutput, encrypted.length);
                    fileOutput.write(encrypted);
                    
                    System.out.println("[WRITE-CHUNKED] Chunk " + chunkIndex + ": " + 
                                     plaintext.length + " -> " + encrypted.length + " bytes");
                    
                    chunkIndex++;
                    
                    // Clear sensitive data
                    Arrays.fill(plaintext, (byte) 0);
                }
                
                // Reset buffer
                buffer.reset();
                
            } catch (GeneralSecurityException e) {
                throw new IOException("Encryption failed for chunk " + chunkIndex, e);
            }
        }
        
        /**
         * Write file header with metadata
         */
        private void writeHeader() throws IOException {
            // Header format: MAGIC(4) + VERSION(2) + CHUNK_SIZE(4) + ORIGINAL_SIZE(8) + PADDING
            byte[] magic = "CENC".getBytes();
            fileOutput.write(magic);
            writeShort(fileOutput, (short) 1);
            writeInt(fileOutput, chunkSize);
            writeLong(fileOutput, totalBytesWritten); // We'll update this on close
            
            // Padding to 32 bytes
            byte[] padding = new byte[14];
            fileOutput.write(padding);
            
            System.out.println("[WRITE-CHUNKED] Header written");
        }
        
        /**
         * Encrypt chunk data using the crypto service
         */
        private byte[] encryptChunkData(byte[] plaintext, String associatedData) 
                throws GeneralSecurityException, IOException {
            // Extract chunk index from associated data
            String[] parts = associatedData.split(":chunk:");
            int chunkIdx = Integer.parseInt(parts[parts.length - 1]);
            return crypto.encryptChunk(plaintext, filename, chunkIdx);
        }
        
        @Override
        public int read(ByteBuffer dst) throws IOException {
            throw new UnsupportedOperationException("Write-only channel");
        }
        
        @Override
        public long position() {
            return totalBytesWritten;
        }
        
        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            // SSHD may call position() to query current position or validate offsets
            // We support querying current position but not arbitrary seeks
            if (newPosition == totalBytesWritten) {
                // No-op: already at this position (SSHD validation)
                return this;
            }
            
            if (newPosition < totalBytesWritten) {
                // Backward seek not supported in streaming write
                throw new IOException("Cannot seek backwards in write-only channel (position: " + 
                                    totalBytesWritten + ", requested: " + newPosition + ")");
            }
            
            if (newPosition > totalBytesWritten) {
                // Forward seek - write zeros to fill gap (sparse file behavior)
                long gap = newPosition - totalBytesWritten;
                if (gap > 10 * 1024 * 1024) { // Sanity check: max 10MB gap
                    throw new IOException("Seek gap too large: " + gap + " bytes");
                }
                
                // Fill with zeros
                byte[] zeros = new byte[(int) Math.min(gap, 8192)];
                ByteBuffer zeroBuf = ByteBuffer.wrap(zeros);
                while (gap > 0) {
                    int toWrite = (int) Math.min(gap, zeros.length);
                    zeroBuf.clear();
                    zeroBuf.limit(toWrite);
                    write(zeroBuf);
                    gap -= toWrite;
                }
            }
            
            return this;
        }
        
        @Override
        public long size() {
            return totalBytesWritten;
        }
        
        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            if (!open) throw new IOException("Channel closed");
            
            if (size < 0) {
                throw new IllegalArgumentException("Negative size: " + size);
            }
            
            if (size >= totalBytesWritten) {
                // Truncate to current or larger size is no-op
                return this;
            }
            
            // Truncating to smaller size not supported in streaming mode
            // This would require rewriting already-encrypted chunks
            throw new IOException("Cannot truncate write-only channel to smaller size " +
                                "(current: " + totalBytesWritten + ", requested: " + size + ")");
        }
        
        @Override
        public boolean isOpen() {
            return open;
        }
        
        @Override
        public void close() throws IOException {
            if (!open) return;
            
            try {
                // Flush any remaining data
                flushChunk(true);
                
                // Update header with final size
                if (headerWritten) {
                    updateHeaderSize();
                }
                
                fileOutput.flush();
                fileOutput.close();
                
                System.out.println("[WRITE-CHUNKED] Completed: " + filename + 
                                 " (" + totalBytesWritten + " bytes, " + chunkIndex + " chunks)");
                
            } finally {
                open = false;
            }
        }
        
        /**
         * Update the original size in the header
         */
        private void updateHeaderSize() throws IOException {
            try (RandomAccessFile raf = new RandomAccessFile(targetFile.toFile(), "rw")) {
                // Seek to size field (offset 10: MAGIC(4) + VERSION(2) + CHUNK_SIZE(4))
                raf.seek(10);
                writeLongToRAF(raf, totalBytesWritten);
            }
        }
        
        // Helper methods
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
        
        private void writeLongToRAF(RandomAccessFile raf, long value) throws IOException {
            raf.write((int) (value >> 56) & 0xFF);
            raf.write((int) (value >> 48) & 0xFF);
            raf.write((int) (value >> 40) & 0xFF);
            raf.write((int) (value >> 32) & 0xFF);
            raf.write((int) (value >> 24) & 0xFF);
            raf.write((int) (value >> 16) & 0xFF);
            raf.write((int) (value >> 8) & 0xFF);
            raf.write((int) value & 0xFF);
        }
    }
}