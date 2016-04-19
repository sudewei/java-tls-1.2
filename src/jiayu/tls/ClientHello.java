package jiayu.tls;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * An object that represents a TLS 1.2 ClientHello handshake record.
 * <p>
 * Standards based as far as possible, lacking in support for compression methods (defaults to no compression)
 * and extensions (not supported).
 */
public class ClientHello extends HandshakeMessage {
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

        length = 2                    // client version (2 content)
                + 32                  // random (32 content)
                + 1                   // sessionid.length (1 byte)
                + sessionId.length    // sessionid (sessionid.length)
                + 2                   // ciphersuiteslength (2 content)
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
     * Interpret a generic handshake message as a ClientHello
     *
     * @param handshake A handshake message expected to be a ClientHello
     * @return The extracted ClientHello
     * @throws FatalAlertException If a fatal error occurred while interpreting the handshake
     */
    static ClientHello interpret(GenericHandshakeMessage handshake) throws FatalAlertException {
        if (handshake.getType() != HandshakeType.CLIENT_HELLO)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        ByteBuffer content = ByteBuffer.wrap(handshake.getContent());

        short clientVersion = content.getShort();                           // get 2 content
        Random random = Random.fromBytes(content);                          // get 32 content
        byte sessionIdLength = content.get();                               // get 1 byte
        byte[] sessionIdBytes = new byte[sessionIdLength];
        content.get(sessionIdBytes);                                        // get sessionid.length content
        UIntVector sessionId = new UIntVector(sessionIdBytes);

        short cipherSuitesLength = content.getShort();                      // get 2 content
        CipherSuite[] cipherSuites =
                new CipherSuite[cipherSuitesLength / Short.BYTES];

        for (int i = 0; i < cipherSuitesLength / Short.BYTES; i++)          // get ciphersuitelength content
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
        return String.format("    client_version: %s", Integer.toHexString(clientVersion)) +
                String.format("%n    random: %s", DatatypeConverter.printBase64Binary(random.toBytes())) +
                String.format("%n    session_id: %d", sessionId.getValue()) +
                String.format("%n    cipher_suites: %s", Arrays.toString(cipherSuites)) +
                String.format("%n    compression_methods: %s", Arrays.toString(compressionMethods));
    }
}
