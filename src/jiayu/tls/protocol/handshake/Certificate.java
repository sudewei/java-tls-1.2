package jiayu.tls.protocol.handshake;

import java.nio.ByteBuffer;

public class Certificate extends Handshake {
    private byte[] certificate;

    public Certificate(byte[] certificate) {
        super(HandshakeType.CERTIFICATE);
        this.certificate = certificate;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    private static Certificate createFrom(Handshake handshake) {
        ByteBuffer buf = ByteBuffer.wrap(handshake.getContent());
        int length = buf.getInt();
        byte[] certificate = new byte[length];

        buf.get(certificate);

        return new Certificate(certificate);
    }

    public byte[] getBytes() {
        return ByteBuffer.allocate(Integer.BYTES + certificate.length)
                .putInt(certificate.length)
                .put(certificate)
                .array();
    }

    @Override
    public byte[] getContent() {
        return getBytes();
    }
}
