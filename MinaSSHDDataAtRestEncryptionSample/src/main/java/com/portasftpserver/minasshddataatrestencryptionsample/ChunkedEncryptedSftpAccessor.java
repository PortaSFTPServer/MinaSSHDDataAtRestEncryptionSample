package com.portasftpserver.minasshddataatrestencryptionsample;

import org.apache.sshd.sftp.server.*;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.FileAttribute;
import java.util.Set;

/**
 * SFTP file system accessor with chunked encryption support. Compatible with
 * Apache MINA SSHD 2.16.0.
 *
 * Features: - Chunk-based encryption for large files - Streaming processing (no
 * full file in memory) - Random access support for reads - Configurable .enc
 * extension mode
 *
 * Modes: - useEncExtension = false: Files stored with original names
 * (recommended) - useEncExtension = true: Files stored with .enc suffix
 */
public class ChunkedEncryptedSftpAccessor implements SftpFileSystemAccessor {

    private static final String ENC_SUFFIX = ".enc";
    private final ChunkedEncryptionService crypto;
    private final boolean useEncExtension;

    /**
     * @param crypto Chunked encryption service
     * @param useEncExtension true = use .enc extension, false = no extension
     */
    public ChunkedEncryptedSftpAccessor(ChunkedEncryptionService crypto, boolean useEncExtension) {
        this.crypto = crypto;
        this.useEncExtension = useEncExtension;

        System.out.println("[CONFIG] Chunked encryption accessor initialized");
        System.out.println("  - Extension mode: "
                + (useEncExtension ? "ENABLED (.enc suffix)" : "DISABLED (original names)"));
        System.out.println("  - Chunk size: " + crypto.getChunkSize() + " bytes");
    }

    @Override
    public SeekableByteChannel openFile(SftpSubsystemProxy subsystem, FileHandle fileHandle,
            Path file, String handle, Set<? extends OpenOption> options,
            FileAttribute<?>[] attrs) throws IOException {

        String filename = file.getFileName().toString();

        // Determine logical filename and physical path based on mode
        String logicalFilename;
        Path physicalPath;

        if (useEncExtension) {
            // MODE 1: With .enc extension
            // Client sees and requests files WITH .enc
            logicalFilename = filename.endsWith(ENC_SUFFIX)
                    ? filename.substring(0, filename.length() - ENC_SUFFIX.length())
                    : filename;

            physicalPath = filename.endsWith(ENC_SUFFIX)
                    ? file
                    : file.resolveSibling(filename + ENC_SUFFIX);
        } else {

            // MODE 2: No .enc extension
            // Files stored with original names (encrypted content)
            logicalFilename = filename;
            physicalPath = file;

        }

        boolean read = options.contains(StandardOpenOption.READ);
        boolean write = options.contains(StandardOpenOption.WRITE)
                || options.contains(StandardOpenOption.CREATE)
                || options.contains(StandardOpenOption.CREATE_NEW);

        System.out.println("[OPEN-CHUNKED] Logical: " + logicalFilename + " | Physical: "
                + physicalPath.getFileName() + " | R:" + read + " W:" + write);

        // Handle different open modes
        if (write && read) {
            // SSHD sometimes opens with both flags for append operations
            // Check if file exists to determine mode
            if (Files.exists(physicalPath)) {
                // Existing file: open for reading (most common case)
                System.out.println("[OPEN-CHUNKED] Both R+W specified, file exists -> READ mode");
                return new ChunkedEncryptedChannels.ChunkedReadChannel(
                        physicalPath, logicalFilename, crypto);
            } else {
                // New file: open for writing
                System.out.println("[OPEN-CHUNKED] Both R+W specified, new file -> WRITE mode");
                return new ChunkedEncryptedChannels.ChunkedWriteChannel(
                        physicalPath, logicalFilename, crypto);
            }
        } else if (write) {
            // Write-only mode
            return new ChunkedEncryptedChannels.ChunkedWriteChannel(
                    physicalPath, logicalFilename, crypto);
        } else if (read) {
            // Read-only mode
            if (!Files.exists(physicalPath)) {
                throw new NoSuchFileException(logicalFilename);
            }
            return new ChunkedEncryptedChannels.ChunkedReadChannel(
                    physicalPath, logicalFilename, crypto);
        }

        // Default: use standard FileChannel for other operations
        return FileChannel.open(physicalPath, options, attrs);
    }
}
