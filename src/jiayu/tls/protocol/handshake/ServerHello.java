package jiayu.tls.protocol.handshake;

import java.nio.ByteBuffer;

public class ServerHello extends Handshake {
    public static final int LENGTH = Random.BYTES + Integer.BYTES + CipherSuite.BYTES;

    private Random random;
    private int sessionId;
    private CipherSuite cipherSuite;

    private ServerHello(Random random, int sessionId, CipherSuite cipherSuite) {
        super(HandshakeType.SERVER_HELLO);

        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuite = cipherSuite;
    }

    public Random getRandom() {
        return random;
    }

    public int getSessionId() {
        return sessionId;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    private static ServerHello createFrom(Handshake handshake) {
        ByteBuffer buf = ByteBuffer.wrap(handshake.getContent());

        Random random = Random.fromBytes(buf);
        int sessionId = buf.getInt();
        CipherSuite cipherSuite = CipherSuite.fromValue(buf.getShort());

        return new ServerHello(random, sessionId, cipherSuite);

    }

    @Override
    public byte[] getContent() {
        return new byte[0];
    }
}
