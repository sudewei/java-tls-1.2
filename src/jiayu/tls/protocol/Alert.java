package jiayu.tls.protocol;

import java.nio.ByteBuffer;

public class Alert implements ProtocolMessage {
    public static final int BYTES = 2;

    private final AlertLevel level;
    private final AlertDescription description;

    private Alert(AlertLevel level, AlertDescription description) {
        this.level = level;
        this.description = description;
    }

    public byte[] toBytes() {
        return ByteBuffer.allocate(2)
                .put(level.value)
                .put(description.value)
                .array();
    }

    public static Alert fatal(AlertDescription desc) {
        return new Alert(AlertLevel.FATAL, desc);
    }

    public static Alert unexpectedMessageAlert() {
        return new Alert(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @Override
    public ContentType getContentType() {
        return ContentType.ALERT;
    }

    @Override
    public byte[] getContent() {
        return new byte[]{level.value, description.value};
    }

    private enum AlertLevel {
        WARNING(1), FATAL(2);

        public final byte value;

        AlertLevel(int value) {
            assert value <= 0xFF;
            this.value = (byte) value;
        }
    }

    public enum AlertDescription {
        CLOSE_NOTIFY(0), UNEXPECTED_MESSAGE(10), HANDSHAKE_FAILURE(40), BAD_CERTIFICATE(42),
        CERTIFICATE_EXPIRED(45), DECRYPT_ERROR(51), INTERNAL_ERROR(80);

        public final byte value;

        AlertDescription(int value) {
            assert value <= 0xFF;
            this.value = (byte) value;
        }
    }
}
