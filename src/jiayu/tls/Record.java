package jiayu.tls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;

public class Record {
    public static final short PROTOCOL_VERSION = 0x0303;

    private final int length;
    private final ContentType contentType;
    private final short protocolVersion;
    private final byte[] content;

    public Record(ContentType contentType, short protocolVersion, byte[] content) {
        this.contentType = contentType;
        this.protocolVersion = protocolVersion;
        this.content = content;

        length = 1 + 2 + 2 + content.length;
    }

    public Record(ProtocolMessage message) {
        this(message.getContentType(), PROTOCOL_VERSION, message.getContent());
    }

    public ContentType getContentType() {
        return contentType;
    }

    public byte[] getContent() {
        return Arrays.copyOf(content, content.length);
    }

    public static Record readFrom(ReadableByteChannel src) throws IOException {
        // content type + protocol version + content length
        ByteBuffer buf = ByteBuffer.allocate(1 + Short.BYTES + Integer.BYTES);
        src.read(buf);
        buf.flip();
        ContentType contentType = ContentType.valueOf(buf.get());
        short protocolVersion = buf.getShort();
        int length = buf.getInt();

        buf = ByteBuffer.allocate(length);
        src.read(buf);
        byte[] body = buf.array();

        return new Record(contentType, protocolVersion, body);
    }

    public int getLength() {
        return length;
    }

    public byte[] getBytes() {
        return ByteBuffer.allocate(length)
                .put(contentType.value)
                .putShort(protocolVersion)
                .putShort((short) content.length)
                .put(content)
                .array();
    }

    public byte[] toBytes(byte[] body) {
        // contentType + protocol version + content length + content
        int length = 1 + Short.BYTES + Short.BYTES + body.length;

        return ByteBuffer.allocate(length)
                .put(contentType.value)
                .putShort(PROTOCOL_VERSION)
                .putInt(body.length)
                .put(body)
                .array();
    }

//    public ReadableByteChannel toReadableByteChannel() {
//        int length = 1 + content.length;
//        return Channels.newChannel(
//                new ByteArrayInputStream(
//                        ByteBuffer.allocate(Integer.BYTES + length)
//                                .putInt(length)
//                                .put(contentType.content)
//                                .put(content)
//                                .array()
//                ));
//    }

}
