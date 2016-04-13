package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import javax.xml.bind.DatatypeConverter;
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

        System.out.println(DatatypeConverter.printHexBinary(message.getContent()));

        ByteBuffer buf = ByteBuffer.wrap(message.getContent());

        byte type = buf.get();                                           // get 1 byte
        if (HandshakeType.valueOf(type) != HandshakeType.CLIENT_HELLO)
            throw new UnexpectedMessageException();

        byte[] lengthBytes = new byte[3];
        buf.get(lengthBytes);                                            // get 3 bytes
        int length = UIntVector.btoi(lengthBytes);

        short clientVersion = buf.getShort();                            // get 2 bytes
        Random random = Random.fromBytes(buf);                           // get 32 bytes
        byte sessionIdLength = buf.get();                                // get 1 byte
        byte[] sessionIdBytes = new byte[sessionIdLength];
        buf.get(sessionIdBytes);                                         // get sessionid.length bytes
        UIntVector sessionId = new UIntVector(sessionIdBytes);

        short cipherSuitesLength = buf.getShort();                       // get 2 bytes
        CipherSuite[] cipherSuites =
                new CipherSuite[cipherSuitesLength / Short.BYTES];

        for (int i = 0; i < cipherSuitesLength / Short.BYTES; i++)       // get ciphersuitelength bytes
            cipherSuites[i] = CipherSuite.fromValue(buf.getShort());

        byte compressionMethodsLength = buf.get();                       // get 1 byte
        byte[] compressionMethods = new byte[compressionMethodsLength];
        buf.get(compressionMethods);                                     // get 1 byte

        return new ClientHello(clientVersion, random, sessionId, cipherSuites, compressionMethods);
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }

//    /**
//     * Attempts to read a ClientHello message from a ReadableByteChannel.
//     * <p>
//     * Expects to receive only a ClientHello message, otherwise will throw an UnexpectedMessageException.
//     *
//     * @param src The channel to read from
//     * @return A new ClientHello object
//     * @throws IOException                If an I/O error occurs
//     * @throws UnexpectedMessageException If an unexpected message was received
//     */
//    public static ClientHello tryToReadFrom(ReadableByteChannel src) throws IOException {
//        Handshake handshake = Handshake.tryToReadFrom(src);
//
//        if (handshake.valueOf() != HandshakeType.CLIENT_HELLO) {
//            throw new UnexpectedMessageException();
//        }
//
//        return ClientHello.createFrom(handshake);
//    }
//
//    private static ClientHello createFrom(Handshake handshake) {
//        ByteBuffer buf = ByteBuffer.wrap(handshake.getContent());
//
//        short clientVersion = buf.getShort();
//        Random random = Random.fromBytes(buf);
//        int sessionId = buf.getInt();
//        int cipherSuitesLength = buf.getInt();
//        short[] cipherSuitesValues = new short[cipherSuitesLength / 2];
//        for (int i = 0; i < cipherSuitesLength / 2; i++) {
//            cipherSuitesValues[i] = buf.getShort();
//        }
//        List<CipherSuite> cipherSuites = CipherSuite.fromValues(cipherSuitesValues);
//
//        return new ClientHello(clientVersion, random, sessionId, cipherSuitesLength, cipherSuites);
//    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("client_version: %s", Integer.toHexString(clientVersion)))
                .append(String.format("random: %s", Arrays.toString(random.toBytes())))
                .append(String.format("session_id: %d", sessionId.getValue()))
                .append(String.format("cipher_suites", Arrays.toString(cipherSuites)))
                .append(String.format("compression_methods: %s", Arrays.toString(compressionMethods)));

        return sb.toString();
    }
}
