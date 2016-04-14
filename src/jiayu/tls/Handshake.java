package jiayu.tls;

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
                .put(UInt.itob(length, 3))
                .array();
    }

    static int interpretHeader(ByteBuffer content, HandshakeType expectedType) throws FatalAlertException {
        byte type = content.get();
        byte[] lengthBytes = new byte[3];
        content.get(lengthBytes);

        if (HandshakeType.valueOf(type) != expectedType)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        return UInt.btoi(lengthBytes);
    }

    @Override
    public ContentType getContentType() {
        return ContentType.HANDSHAKE;
    }
}
