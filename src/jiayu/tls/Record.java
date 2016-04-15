package jiayu.tls;

import java.nio.ByteBuffer;

public interface Record {
    short PROTOCOL_VERSION = 0x0303;
    int HEADER_LENGTH = 5;

    ContentType getContentType();

    short getProtocolVersion();

    byte[] getContent();

    byte[] toBytes();

    default byte[] getHeader() {
        assert getContent().length <= Short.MAX_VALUE;
        return ByteBuffer.allocate(HEADER_LENGTH)
                .put(getContentType().value)
                .putShort(getProtocolVersion())
                .putShort((short) getContent().length)
                .array();
    }
}
