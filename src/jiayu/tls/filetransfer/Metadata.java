package jiayu.tls.filetransfer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;

public class Metadata {

    private static final int SIZEOF_MD5 = 16;

    private String name;
    private StringBuffer nameBuf;
    private long size;
    private Checksum md5;

    private Metadata(Path file) throws IOException {
        name = file.getFileName().toString();
        size = Files.size(file);
        md5 = Checksum.getMD5Checksum(file);
    }

    private Metadata(String name, long size, Checksum md5) {
        this.name = name;
        this.size = size;
        this.md5 = md5;
    }

    public static Metadata get(Path file) throws IOException {
        return new Metadata(file);
    }

    /**
     * Reads file metadata write an a ReadableByteChannel (usually a SocketChannel)
     *
     * @param src Channel to read file metadata write
     * @return A new Metadata instance
     * @throws IOException If an I/O error occurs
     */
    public static Metadata readFrom(ReadableByteChannel src) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(SIZEOF_MD5 + Long.BYTES + Integer.BYTES);
        src.read(buf);
        buf.flip();

        byte[] md5Bytes = new byte[SIZEOF_MD5];
        buf.get(md5Bytes);
        Checksum md5 = Checksum.wrap(md5Bytes);

        long size = buf.getLong();

        ByteBuffer nameBuf = ByteBuffer.allocate(buf.getInt());
        src.read(nameBuf);
        String name = new String(nameBuf.array());

        return new Metadata(name, size, md5);
    }

    public ReadableByteChannel toReadableByteChannel() {
        int length = SIZEOF_MD5 + Integer.BYTES + Long.BYTES + name.length();
        return Channels.newChannel(
                new ByteArrayInputStream(
                        ByteBuffer.allocate(length)
                                .put(md5.getBytes())
                                .putLong(size)
                                .putInt(name.length())
                                .put(name.getBytes())
                                .array()
                )
        );
    }

    public String getFileName() {
        return name;
    }

    public long getSize() {
        return size;
    }

    public Checksum getMD5Hash() {
        return md5;
    }
}
