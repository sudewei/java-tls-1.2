package jiayu.tls;

import java.nio.ByteBuffer;
import java.util.Arrays;

abstract class AbstractRecord implements Record {
    private final ContentType contentType;
    private final short protocolVersion;
    private final byte[] content;

    AbstractRecord(ContentType contentType, short protocolVersion, byte[] content) {
        this.contentType = contentType;
        this.protocolVersion = protocolVersion;
        this.content = content;
    }

    @Override
    public ContentType getContentType() {
        return contentType;
    }

    @Override
    public short getProtocolVersion() {
        return protocolVersion;
    }

    @Override
    public byte[] getContent() {
        return Arrays.copyOf(content, content.length);
    }

    @Override
    public byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + getContent().length)
                .put(getHeader())
                .put(getContent())
                .array();
    }
}
