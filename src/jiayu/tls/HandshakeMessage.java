package jiayu.tls;

import java.nio.ByteBuffer;

public abstract class HandshakeMessage implements ProtocolMessage {
    public static final ContentType CONTENT_TYPE = ContentType.HANDSHAKE;
    public static final int HEADER_LENGTH = 4;

    private final HandshakeType handshakeType;

    HandshakeMessage(HandshakeType handshakeType) {
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

    HandshakeType getHandshakeType(GenericHandshakeMessage handshake) {
        return handshake.getType();
    }

    int getHandshakeLength(GenericHandshakeMessage handshake) {
        return handshake.getLength();
    }

    byte[] getHandshakeContent(GenericHandshakeMessage handshake) {
        return handshake.getContent();
    }

    @Override
    public ContentType getContentType() {
        return ContentType.HANDSHAKE;
    }
}
