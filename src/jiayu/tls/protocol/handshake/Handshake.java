package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import java.nio.ByteBuffer;

public abstract class Handshake implements ProtocolMessage {
    public static final ContentType CONTENT_TYPE = ContentType.HANDSHAKE;
    public static final int HEADER_LENGTH = 4;

    private final HandshakeType handshakeType;

    Handshake(HandshakeType handshakeType) {
        this.handshakeType = handshakeType;
    }

    byte[] createHeader(int length) {
        return ByteBuffer.allocate(HEADER_LENGTH)
                .put(handshakeType.value)
                .put(UIntVector.itob(length, 3))
                .array();
    }

    static int interpretHeader(ByteBuffer content, HandshakeType expectedType) throws UnexpectedMessageException {
        byte type = content.get();
        byte[] lengthBytes = new byte[3];
        content.get(lengthBytes);

        if (HandshakeType.valueOf(type) != expectedType)
            throw new UnexpectedMessageException();

        return UIntVector.btoi(lengthBytes);
    }

    @Override
    public ContentType getContentType() {
        return ContentType.HANDSHAKE;
    }
}
