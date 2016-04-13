package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class ServerHello extends Handshake implements ProtocolMessage {
    private static final short SERVER_VERSION = 0x0303;
    private static final byte COMPRESSION_METHOD = 0x00;

    private final int length;
    private final byte[] header;

    private final short serverVersion;
    private final Random random;
    private final UIntVector sessionId;
    private final CipherSuite cipherSuite;
    private final byte compressionMethod;

    public ServerHello(CipherSuite selectedCipherSuite) {
        this(
                new SecureRandom().nextInt(),
                selectedCipherSuite
        );
    }

    public ServerHello(int sessionId, CipherSuite selectedCipherSuite) {
        this(
                SERVER_VERSION,
                new Random(),
                new UIntVector(sessionId),
                selectedCipherSuite,
                COMPRESSION_METHOD
        );
    }

    private ServerHello(short serverVersion, Random random, UIntVector sessionId, CipherSuite cipherSuite, byte compressionMethod) {
        super(HandshakeType.SERVER_HELLO);

        this.serverVersion = serverVersion;
        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuite = cipherSuite;
        this.compressionMethod = COMPRESSION_METHOD;

        length = 2                  // server version (2 bytes)
                + 32                // random (32 bytes)
                + 1                 // sessionid.length (1 byte)
                + sessionId.length  // sessionid (sessionid.length)
                + 2                 // selected cipher suite (2 bytes)
                + 1;                // selected compression method (1 byte)

        header = createHeader(length);
    }

    public short getServerVersion() {
        return serverVersion;
    }

    public Random getRandom() {
        return random;
    }

    public int getSessionId() {
        return sessionId.getValue();
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }


    @Override
    public byte[] getContent() {
        return new byte[0];
    }

    public static ServerHello interpret(ProtocolMessage message) throws UnexpectedMessageException {
        if (message.getContentType() != ContentType.HANDSHAKE)
            throw new UnexpectedMessageException();

        ByteBuffer content = ByteBuffer.wrap(message.getContent());

        int length = interpretHeader(content, HandshakeType.SERVER_HELLO);

        short serverVersion = content.getShort();
        Random random = Random.fromBytes(content);

        byte sessionIdLength = content.get();
        byte[] sessionIdBytes = new byte[sessionIdLength];
        content.get(sessionIdBytes);
        UIntVector sessionId = new UIntVector(sessionIdBytes);

        CipherSuite cipherSuite = CipherSuite.fromValue(content.getShort());
        byte compressionMethod = content.get();

        return new ServerHello(serverVersion, random, sessionId, cipherSuite, compressionMethod);
    }
}
