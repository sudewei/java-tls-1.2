package jiayu.tls;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CertificateList implements Vector<ASN1Cert> {
    public static final int LENGTH_BYTES = 3;

    private final byte[] length;
    private final int certificatesLength;
    private final ArrayList<ASN1Cert> certificates;


    CertificateList(ASN1Cert... certs) {
        this(Arrays.asList(certs));
    }

    private CertificateList(List<ASN1Cert> certs) {
        int certificatesLength = 0;
        this.certificates = new ArrayList<>();

        for (ASN1Cert certificate : certs) {
            certificatesLength += certificate.getEntireLength();
            this.certificates.add(certificate);
        }

        this.certificatesLength = certificatesLength;
        this.length = UInt.itob(LENGTH_BYTES + certificatesLength, LENGTH_BYTES);
    }


    static CertificateList fromBytes(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        ArrayList<ASN1Cert> certificateList = new ArrayList<>();

        byte[] length = new byte[3];

        while (buf.hasRemaining()) {
            buf.get(length);
            int nextCertLength = UInt.btoi(length);

            byte[] nextCertBytes = new byte[nextCertLength];
            buf.get(nextCertBytes);

            certificateList.add(new ASN1Cert(nextCertBytes));
        }

        return new CertificateList(certificateList);
    }

    @Override
    public List<ASN1Cert> getContents() {
        return certificates;
    }

    @Override
    public int getEntireLength() {
        return LENGTH_BYTES + certificatesLength;
    }

    @Override
    public int getLengthFieldLength() {
        return LENGTH_BYTES;
    }

    @Override
    public int getContentLength() {
        return certificatesLength;
    }

    @Override
    public byte[] getContent() {
        ByteBuffer buf = ByteBuffer.allocate(certificatesLength);
        certificates.forEach(asn1Cert -> buf.put(asn1Cert.toBytes()));
        return buf.array();
    }

    @Override
    public byte[] toBytes() {
        return ByteBuffer.allocate(getEntireLength())
                .put(length)
                .put(getContent())
                .array();
    }
}
