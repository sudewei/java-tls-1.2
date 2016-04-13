package jiayu.tls.protocol.handshake;

public class ServerHelloDone extends Handshake {
    public ServerHelloDone() {
        super(HandshakeType.SERVER_HELLO_DONE);
    }

    private static ServerHelloDone createFrom(Handshake handshake) {
        return new ServerHelloDone();
    }

    @Override
    public byte[] getContent() {
        return new byte[0];
    }
}
