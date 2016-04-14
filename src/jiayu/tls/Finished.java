package jiayu.tls;

public class Finished extends Handshake {
    Finished() {
        super(HandshakeType.FINISHED);
    }

    @Override
    public byte[] getContent() {
        return new byte[0];
    }
}
