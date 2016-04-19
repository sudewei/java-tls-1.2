package jiayu.tls.filetransfer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Metadata {
    private static final int SHA_256_BYTES = 32;

    private final String filename;
    private final int filesize;
    private final byte[] checksum;

    private final int length;

    public Metadata(String filename, byte[] content) {
        this(filename,
                content.length,
                calculateChecksum(content));
    }

    private Metadata(Path file) throws IOException {
        this(file.getFileName().toString(),
                (int) Files.size(file),
                calculateChecksum(file));
    }

    private Metadata(String filename, int filesize, byte[] checksum) {
        this.filename = filename;
        this.filesize = filesize;
        this.checksum = checksum;

        length = Integer.BYTES + filename.length() + Integer.BYTES + SHA_256_BYTES;
    }

    public static Metadata get(Path file) throws IOException {
        return new Metadata(file);
    }

    public String getFilename() {
        return filename;
    }

    public int getFilesize() {
        return filesize;
    }

    public byte[] getChecksum() {
        return checksum;
    }

    public byte[] getBytes() {
        return ByteBuffer.allocate(Integer.BYTES + length)
                .putInt(length)
                .putInt(filename.length())
                .put(filename.getBytes())
                .putInt(filesize)
                .put(checksum)
                .array();
    }

    public static Metadata fromBytes(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        int filenameLength = buf.getInt();
        byte[] filenameBytes = new byte[filenameLength];
        buf.get(filenameBytes);
        String filename = new String(filenameBytes);
        int filesize = buf.getInt();
        byte[] checksum = new byte[SHA_256_BYTES];
        buf.get(checksum);

        return new Metadata(filename, filesize, checksum);
    }

    public static byte[] calculateChecksum(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

    }

    public static byte[] calculateChecksum(Path file) throws IOException {
        return calculateChecksum(Files.readAllBytes(file));
    }
}
