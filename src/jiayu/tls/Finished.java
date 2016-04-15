package jiayu.tls;

public class Finished extends HandshakeMessage {
    Finished() {
        super(HandshakeType.FINISHED);
    }

    @Override
    public byte[] getContent() {
        return new byte[0];
    }
}
