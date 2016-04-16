package jiayu.tls;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Finished extends HandshakeMessage {
    private static final String CLIENT_FINISHED_LABEL = "client finished";
    private static final String SERVER_FINISHED_LABEL = "server finished";
    private static final int VERIFY_DATA_LENGTH = 12;

    private final int length;
    private final byte[] header;

    private final byte[] verifyData;

    private Finished(byte[] verifyData) {
        super(HandshakeType.FINISHED);

        this.verifyData = verifyData;

        length = verifyData.length;
        header = createHeader(length);
    }

    // FIXME: 15/04/2016 should use security parameters
    public static Finished createClientFinishedMessage(MasterSecret masterSecret,
                                                       ClientHello clientHello,
                                                       ServerHello serverHello,
                                                       Certificate certificate,
                                                       ServerHelloDone serverHelloDone,
                                                       ClientKeyExchange clientKeyExchange) throws FatalAlertException {

        String finishedLabel = CLIENT_FINISHED_LABEL;

        byte[] hash = concatAndHash("SHA-256",
                clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange);

        byte[] verifyData = PRF(masterSecret, finishedLabel, hash);

        return new Finished(verifyData);
    }

    public void verify(Finished ours, Finished theirs) throws FatalAlertException {
        if (!Arrays.equals(ours.verifyData, theirs.verifyData)) {
            throw new FatalAlertException(AlertDescription.DECRYPT_ERROR);
        }
    }

    // FIXME: 15/04/2016 should use security parameters
    public static Finished createServerFinishedMessage(MasterSecret masterSecret,
                                                       ClientHello clientHello,
                                                       ServerHello serverHello,
                                                       Certificate certificate,
                                                       ServerHelloDone serverHelloDone,
                                                       ClientKeyExchange clientKeyExchange,
                                                       Finished clientFinished) throws FatalAlertException {
        String finishedLabel = SERVER_FINISHED_LABEL;

        byte[] hash = concatAndHash("SHA-256",
                clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange, clientFinished);

        byte[] verifyData = PRF(masterSecret, finishedLabel, hash);

        return new Finished(verifyData);
    }

    private static byte[] concatAndHash(String algorithm, HandshakeMessage... handshakeMessages) throws FatalAlertException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
        }

        for (HandshakeMessage handshakeMessage : handshakeMessages) {
            md.update(handshakeMessage.getContent());
        }

        return md.digest();
    }

    private static byte[] PRF(MasterSecret masterSecret, String finishedLabel, byte[] hash) throws FatalAlertException {
        Mac hmac;
        try {
            hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(masterSecret.getBytes(), "HmacSHA256"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
        }

        hmac.update(finishedLabel.getBytes());
        hmac.update(hash);

        return Arrays.copyOf(hmac.doFinal(), VERIFY_DATA_LENGTH);
    }

    static Finished interpret(GenericHandshakeMessage handshake) throws FatalAlertException {
        if (handshake.getType() != HandshakeType.FINISHED) {
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);
        }

        return new Finished(handshake.getContent());
    }

    private byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + length)
                .put(header)
                .put(verifyData)
                .array();
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }
}
