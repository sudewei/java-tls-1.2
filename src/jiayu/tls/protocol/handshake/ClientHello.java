package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * An object that represents a TLS 1.2 ClientHello handshake record.
 * <p>
 * Standards based as far as possible, lacking in support for compression methods (defaults to no compression)
 * and extensions (not supported).
 */
public class ClientHello extends Handshake {
    private static final short CLIENT_VERSION = 0x0303;
    private static final byte[] COMPRESSION_METHODS = new byte[]{(byte) 0x00};

    private final int length;
    private final byte[] header;

    private final short clientVersion;
    private final Random random;
    private final UIntVector sessionId;
    private final short cipherSuitesLength;
    private final CipherSuite[] cipherSuites;
    private final byte compressionMethodsLength;
    private final byte[] compressionMethods;

    /**
     * Create a new ClientHello message without specifying a previous session id.
     *
     * @param cipherSuites A list of cipher suites supported by this client
     */
    public ClientHello(CipherSuite... cipherSuites) {
        this(0, cipherSuites);
    }

    /**
     * Create a new ClientHello message, specifying a previous session id to resume.
     *
     * @param sessionId    The previous session id
     * @param cipherSuites A lists of cipher suites supported by this client
     */
    public ClientHello(int sessionId, CipherSuite... cipherSuites) {
        this(
                CLIENT_VERSION,
                new Random(),
                new UIntVector(sessionId),
                cipherSuites,
                COMPRESSION_METHODS
        );
    }

    private ClientHello(short clientVersion, Random random, UIntVector sessionId, CipherSuite[] cipherSuites, byte[] compressionMethods) {
        super(HandshakeType.CLIENT_HELLO);

        this.clientVersion = clientVersion;
        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuitesLength = (short) (cipherSuites.length * 2);
        this.cipherSuites = cipherSuites;
        this.compressionMethodsLength = (byte) compressionMethods.length;
        this.compressionMethods = compressionMethods;

        length = 2                    // client version (2 bytes)
                + 32                  // random (32 bytes)
                + 1                   // sessionid.length (1 byte)
                + sessionId.length    // sessionid (sessionid.length)
                + 2                   // ciphersuiteslength (2 bytes)
                + cipherSuitesLength  // ciphersuites (ciphersuiteslength)
                + 1                   // compressionmethodslength (1 byte)
                + 1;                  // compressionmethods ( 1 byte)

        header = createHeader(length);
    }

    public short getClientVersion() {
        return clientVersion;
    }

    public Random getRandom() {
        return random;
    }

    public int getSessionId() {
        return sessionId.getValue();
    }

    public CipherSuite[] getCipherSuites() {
        return cipherSuites;
    }

    public byte[] getCompressionMethods() {
        return compressionMethods;
    }

    private byte[] toBytes() {
        ByteBuffer content = ByteBuffer.allocate(HEADER_LENGTH + length);
        content.put(header)                           // header
                .putShort(clientVersion)              // client version
                .put(random.toBytes())                // random
                .put(sessionId.length)                // session id length
                .put(sessionId.bytes)                 // session id
                .putShort(cipherSuitesLength);        // cipher suites length
        for (CipherSuite cipherSuite : cipherSuites)  // cipher suites
            content.putShort(cipherSuite.value);
        content.put(compressionMethodsLength)         // compression methods length
                .put(compressionMethods);             // compression methods
        return content.array();
    }

    /**
     * Interpret a generic protocol message as a ClientHello message
     *
     * @param message A message expected to be a ClientHello message
     * @return The extracted ClientHello message
     * @throws UnexpectedMessageException If the record does not contain a valid ClientHello message
     */
    public static ClientHello interpret(ProtocolMessage message) throws UnexpectedMessageException {
        if (message.getContentType() != ContentType.HANDSHAKE)
            throw new UnexpectedMessageException();

        ByteBuffer content = ByteBuffer.wrap(message.getContent());

        int length = interpretHeader(content, HandshakeType.CLIENT_HELLO);  // get 4 bytes

        short clientVersion = content.getShort();                           // get 2 bytes
        Random random = Random.fromBytes(content);                          // get 32 bytes
        byte sessionIdLength = content.get();                               // get 1 byte
        byte[] sessionIdBytes = new byte[sessionIdLength];
        content.get(sessionIdBytes);                                        // get sessionid.length bytes
        UIntVector sessionId = new UIntVector(sessionIdBytes);

        short cipherSuitesLength = content.getShort();                      // get 2 bytes
        CipherSuite[] cipherSuites =
                new CipherSuite[cipherSuitesLength / Short.BYTES];

        for (int i = 0; i < cipherSuitesLength / Short.BYTES; i++)          // get ciphersuitelength bytes
            cipherSuites[i] = CipherSuite.fromValue(content.getShort());

        byte compressionMethodsLength = content.get();                      // get 1 byte
        byte[] compressionMethods = new byte[compressionMethodsLength];
        content.get(compressionMethods);                                    // get 1 byte

        return new ClientHello(clientVersion, random, sessionId, cipherSuites, compressionMethods);
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }

    @Override
    public String toString() {

        return String.format("client_version: %s", Integer.toHexString(clientVersion)) +
                String.format("random: %s", Arrays.toString(random.toBytes())) +
                String.format("session_id: %d", sessionId.getValue()) +
                String.format("cipher_suites", Arrays.toString(cipherSuites)) +
                String.format("compression_methods: %s", Arrays.toString(compressionMethods));
    }
}
