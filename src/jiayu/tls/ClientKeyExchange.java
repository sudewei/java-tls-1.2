package jiayu.tls;

import java.nio.ByteBuffer;

public class ClientKeyExchange extends HandshakeMessage {
    private byte[] encryptedPremasterSecret;

    private ClientKeyExchange() {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
    }

    public byte[] getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    public byte[] getBytes() {
        return ByteBuffer.allocate(encryptedPremasterSecret.length)
                .put(encryptedPremasterSecret)
                .array();
    }

    @Override
    public byte[] getContent() {
        return new byte[0];
    }
}
