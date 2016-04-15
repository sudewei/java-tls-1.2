package jiayu.tls;

import java.nio.ByteBuffer;

// FIXME: 13/04/2016 IMPLEMENT CERTIFICATE CHAIN LENGTH AND CERTIFICATE LENGTH

public class Certificate extends HandshakeMessage {
    private final int length;
    private final byte[] header;

    private final CertificateList certificateList;

    public Certificate(ASN1Cert... certificates) {
        this(new CertificateList(certificates));
    }

    private Certificate(CertificateList certList) {
        super(HandshakeType.CERTIFICATE);

        certificateList = certList;
        length = certList.getEntireLength();
        header = createHeader(length);
    }

    public CertificateList getCertificateList() {
        return certificateList;
    }

    private byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + length)
                .put(header)
                .put(certificateList.toBytes())
                .array();
    }

    public static Certificate interpret(GenericHandshakeMessage handshake) throws FatalAlertException {
        if (handshake.getType() != HandshakeType.CERTIFICATE)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        ByteBuffer content = ByteBuffer.wrap(handshake.getContent());

        // the buffer should now contain 3 content of (certificates length) and
        // (certificates length) content of certificates
        byte[] certListLenBytes = new byte[3];
        content.get(certListLenBytes);

        int certListLength = UInt.btoi(certListLenBytes);
        if (content.remaining() != certListLength)
            throw new FatalAlertException(AlertDescription.DECODE_ERROR);

        byte[] certListBytes = new byte[certListLength];
        content.get(certListBytes);

        CertificateList certList = CertificateList.fromBytes(certListBytes);

        return new Certificate(certList);
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }
}
