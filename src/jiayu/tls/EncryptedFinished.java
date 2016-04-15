package jiayu.tls;

import java.nio.ByteBuffer;

public class EncryptedFinished extends HandshakeMessage {
    private byte[] content;

    public EncryptedFinished(GenericBlockCipher encryptedFinished) {
        super(HandshakeType.FINISHED);

        content = ByteBuffer.allocate(encryptedFinished.getIV().length + encryptedFinished.getCiphertext().length)
                .put(encryptedFinished.getIV())
                .put(encryptedFinished.getCiphertext())
                .array();

    }

    @Override
    public byte[] getContent() {
        return content;
    }
}
