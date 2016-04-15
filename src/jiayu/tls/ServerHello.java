package jiayu.tls;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class ServerHello extends HandshakeMessage {
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

    private ServerHello(int sessionId, CipherSuite selectedCipherSuite) {
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
        this.compressionMethod = compressionMethod;

        length = 2                  // server version (2 content)
                + 32                // random (32 content)
                + 1                 // sessionid.length (1 byte)
                + sessionId.length  // sessionid (sessionid.length)
                + 2                 // selected cipher suite (2 content)
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

    private byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + length)
                .put(header)                  // header
                .putShort(serverVersion)      // server version
                .put(random.toBytes())        // random
                .put(sessionId.length)        // session id length
                .put(sessionId.bytes)         // session id
                .putShort(cipherSuite.value)  // cipher suite
                .put(compressionMethod)       // compression method
                .array();

    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }

    @Override
    public String toString() {

        return String.format("server_version: %s", Integer.toHexString(serverVersion)) +
                String.format("random: %s", Arrays.toString(random.toBytes())) +
                String.format("session_id: %d", sessionId.getValue()) +
                String.format("cipher_suite: %s", Integer.toHexString(cipherSuite.value)) +
                String.format("compression_method: %s", Integer.toHexString(compressionMethod));
    }

    public static ServerHello interpret(GenericHandshakeMessage handshake) throws FatalAlertException {
        if (handshake.getType() != HandshakeType.SERVER_HELLO)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        ByteBuffer content = ByteBuffer.wrap(handshake.getContent());

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
