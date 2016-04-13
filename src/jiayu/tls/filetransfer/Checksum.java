package jiayu.tls.filetransfer;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Checksum {
    // arbitrary limit; above this value files will be buffered
    private static final int SMALL_FILE_THRESHOLD = 2 << 30;

    private byte[] bytes;

    private Checksum() {
        this(new byte[16]);
    }

    private Checksum(byte[] bytes) {
        this.bytes = bytes;
    }

    private Checksum(String algorithm, Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);

        if (Files.size(file) < SMALL_FILE_THRESHOLD) {
            bytes = md.digest(Files.readAllBytes(file));
        } else {
            ByteBuffer buffer = ByteBuffer.allocateDirect(8192);
            try (FileChannel fc = FileChannel.open(file)) {
                while (fc.read(buffer) >= 0 || buffer.position() > 0) {
                    buffer.flip();
                    md.update(buffer);
                    buffer.compact();
                }
                bytes = md.digest();
            }
        }
    }

    public static Checksum wrap(byte[] bytes) {
        return new Checksum(bytes);
    }


    public static Checksum getMD5Checksum(Path file) throws IOException {
        try {
            return new Checksum("MD5", file);
        } catch (NoSuchAlgorithmException e) {
            // MD5 is supported in all java implementations
            assert false;
            return new Checksum();
        }
    }

    public static Checksum getSHA1Checksum(Path file) throws IOException {
        try {
            return new Checksum("SHA-1", file);
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is supported in all java implementations
            assert false;
            return new Checksum();
        }
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String toHexString() {
        return DatatypeConverter.printHexBinary(bytes);
    }

    public boolean compareTo(byte[] other) {
        return Arrays.equals(bytes, other);
    }

    public boolean compareTo(Checksum other) {
        return Arrays.equals(bytes, other.bytes);
    }
}
