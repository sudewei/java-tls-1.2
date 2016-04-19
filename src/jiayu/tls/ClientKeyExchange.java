package jiayu.tls;

import java.nio.ByteBuffer;

public class ClientKeyExchange extends HandshakeMessage {
    private int length;
    private byte[] header;

    private byte[] encryptedPremasterSecret;

    private ClientKeyExchange() {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
    }

    public ClientKeyExchange(byte[] encryptedPremasterSecret) {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);

        this.encryptedPremasterSecret = encryptedPremasterSecret;

        length = encryptedPremasterSecret.length;
        header = createHeader(length);
    }

    public byte[] getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    private byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + length)
                .put(header)
                .put(encryptedPremasterSecret)
                .array();
    }

    static ClientKeyExchange interpret(GenericHandshakeMessage handshake) throws FatalAlertException {
        if (handshake.getType() != HandshakeType.CLIENT_KEY_EXCHANGE) {
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);
        }

        if (handshake.getLength() == 0) {
            throw new FatalAlertException(AlertDescription.DECODE_ERROR);
        }

        return new ClientKeyExchange(handshake.getContent());
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }
}
