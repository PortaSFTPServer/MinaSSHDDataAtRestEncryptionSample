package com.portasftpserver.minasshddataatrestencryptionsample;

import java.io.EOFException;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.server.FileHandle;
import org.apache.sshd.sftp.server.SftpEventListener;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.apache.sshd.sftp.server.Handle;

/**
 * SFTP Event Listener for Apache MINA SSHD 2.16.0
 *
 * CONFIGURABLE VERSION: Adapts based on extension mode
 */
public class EncryptedSftpEventListener implements SftpEventListener {

    private static final String ENC_SUFFIX = ".enc";
    private final boolean useEncExtension;
    
    // Track file handles for friendly messages
    private final Map<String, FileInfo> activeFiles = new HashMap<>();
    
    public EncryptedSftpEventListener(boolean useEncExtension) {
        this.useEncExtension = useEncExtension;
    }
    
    @Override
    public void opening(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
        Path filePath = localHandle.getFile();
        String filename = filePath != null && filePath.getFileName() != null 
            ? filePath.getFileName().toString() 
            : "unknown";
        
        long size = 0;
        try {
            if (filePath != null) {
                size = Files.size(filePath);
            }
        } catch (IOException e) {
            // Ignore - file might not exist yet (for writes)
        }
        
        activeFiles.put(remoteHandle, new FileInfo(filename, size));
        System.out.println("[SFTP-OPEN] " + session.getUsername() + " opened: " + filename + 
                         " (" + formatBytes(size) + ")");
    }
    
    @Override
    public void reading(ServerSession session, String remoteHandle, FileHandle localHandle, 
                       long offset, byte[] data, int dataOffset, int dataLen) throws IOException {
        // Called before read - don't log to reduce noise
    }
    
    @Override
    public void read(ServerSession session, String remoteHandle, FileHandle localHandle, 
                    long offset, byte[] data, int dataOffset, int dataLen, 
                    int readLen, Throwable thrown) throws IOException {
        
        FileInfo info = activeFiles.get(remoteHandle);
        Path filePath = localHandle.getFile();
        String filename = info != null ? info.filename 
            : (filePath != null && filePath.getFileName() != null 
                ? filePath.getFileName().toString() 
                : "unknown");
        
        if (thrown != null) {
            // Check if this is the "normal" EOFException
            if (thrown instanceof EOFException) {
                // This is normal EOF - replace with friendly message
                System.out.println("[SFTP-READ] " + filename + ": End of file reached " +
                                 "(download complete ✓)");
            } else {
                // Real error
                System.err.println("[SFTP-ERROR] " + filename + " read failed: " + thrown.getMessage());
            }
        } else if (readLen > 0) {
            // Successful read - only log occasionally to avoid spam
            if (info != null) {
                info.totalRead += readLen;
                // Log every 10MB or at 25%, 50%, 75%, 100% progress
                long previousTotal = info.totalRead - readLen;
                if (shouldLogProgress(previousTotal, info.totalRead, info.size)) {
                    int percent = (int) ((info.totalRead * 100) / Math.max(info.size, 1));
                    System.out.println("[SFTP-READ] " + filename + ": " + 
                                     formatBytes(info.totalRead) + " / " + 
                                     formatBytes(info.size) + " (" + percent + "%)");
                }
            }
        }
    }
    
    @Override
    public void closed(ServerSession session, String remoteHandle, Handle localHandle, Throwable thrown) throws IOException {
        FileInfo info = activeFiles.remove(remoteHandle);
        if (info != null) {
            System.out.println("[SFTP-CLOSE] " + info.filename + " closed " +
                             "(total: " + formatBytes(info.totalRead) + ")");
        }
    }
    
    @Override
    public void writing(ServerSession session, String remoteHandle, FileHandle localHandle, 
                       long offset, byte[] data, int dataOffset, int dataLen) throws IOException {
        // Called before write
    }
    
    @Override
    public void written(ServerSession session, String remoteHandle, FileHandle localHandle, 
                       long offset, byte[] data, int dataOffset, int dataLen, 
                       Throwable thrown) throws IOException {
        
        FileInfo info = activeFiles.get(remoteHandle);
        Path filePath = localHandle.getFile();
        String filename = info != null ? info.filename 
            : (filePath != null && filePath.getFileName() != null 
                ? filePath.getFileName().toString() 
                : "unknown");
        
        if (thrown != null) {
            System.err.println("[SFTP-ERROR] " + filename + " write failed: " + thrown.getMessage());
        } else if (dataLen > 0) {
            // Successful write
            if (info != null) {
                info.totalWritten += dataLen;
                // Log every 10MB or at milestones
                long previousTotal = info.totalWritten - dataLen;
                if (shouldLogProgress(previousTotal, info.totalWritten, Long.MAX_VALUE)) {
                    System.out.println("[SFTP-WRITE] " + filename + ": " + 
                                     formatBytes(info.totalWritten) + " uploaded");
                }
            }
        }
    }
    
    @Override
    public void removing(ServerSession session, Path path, boolean isDirectory) throws IOException {
        if (!isDirectory && path != null) {
            Path targetPath = useEncExtension ? getEncryptedPath(path) : path;
            if (Files.exists(targetPath)) {
                String filename = path.getFileName() != null 
                    ? path.getFileName().toString() 
                    : path.toString();
                System.out.println("[SFTP-DELETE] " + session.getUsername() + " deleted: " + filename);
            }
        }
    }
    
    @Override
    public void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts) 
            throws IOException {
        if (srcPath == null || dstPath == null) return;
        
        Path encSrc = useEncExtension ? getEncryptedPath(srcPath) : srcPath;
        Path encDst = useEncExtension ? getEncryptedPath(dstPath) : dstPath;
        
        if (Files.exists(encSrc)) {
            Files.move(encSrc, encDst, opts.toArray(new CopyOption[0]));
            
            String srcFilename = srcPath.getFileName() != null 
                ? srcPath.getFileName().toString() 
                : srcPath.toString();
            String dstFilename = dstPath.getFileName() != null 
                ? dstPath.getFileName().toString() 
                : dstPath.toString();
            
            System.out.println("[SFTP-MOVE] " + session.getUsername() + " moved: " + 
                             srcFilename + " → " + dstFilename);
        }
    }
    
    private Path getEncryptedPath(Path path) {
        if (path == null || path.getFileName() == null) {
            return path;
        }
        String filename = path.getFileName().toString();
        if (!filename.endsWith(ENC_SUFFIX)) {
            return path.resolveSibling(filename + ENC_SUFFIX);
        }
        return path;
    }
    
    private boolean shouldLogProgress(long previousTotal, long currentTotal, long totalSize) {
        // Log every 10MB
        long interval = 10 * 1024 * 1024; // 10MB
        if (previousTotal / interval != currentTotal / interval) {
            return true;
        }
        
        // Log at 25%, 50%, 75% milestones
        if (totalSize > 0) {
            int prevPercent = (int) ((previousTotal * 100) / totalSize);
            int currPercent = (int) ((currentTotal * 100) / totalSize);
            
            for (int milestone : new int[]{25, 50, 75}) {
                if (prevPercent < milestone && currPercent >= milestone) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
    
    private static class FileInfo {
        final String filename;
        final long size;
        long totalRead = 0;
        long totalWritten = 0;
        
        FileInfo(String filename, long size) {
            this.filename = filename;
            this.size = size;
        }
    }
}
