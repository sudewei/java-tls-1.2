package jiayu.tls;


import java.nio.ByteBuffer;
import java.util.Arrays;

public class ASN1Cert implements ByteVector {
    private static final int LENGTH_BYTES = 3;

    public final byte[] length;
    public final byte[] content;

    public ASN1Cert(byte[] certificate) {
        length = UInt.itob(certificate.length, LENGTH_BYTES);
        this.content = certificate;
    }

    private ASN1Cert(byte[] length, byte[] content) {
        this.length = length;
        this.content = content;
    }

    public static ASN1Cert fromBytes(byte[] bytes) {
        byte[] length = Arrays.copyOf(bytes, 3);
        byte[] content = Arrays.copyOfRange(bytes, 4, bytes.length);

        return new ASN1Cert(length, content);
    }

    @Override
    public int getEntireLength() {
        return length.length + content.length;
    }

    @Override
    public int getLengthFieldLength() {
        return length.length;
    }

    @Override
    public int getContentLength() {
        return content.length;
    }

    @Override
    public byte[] getContent() {
        return Arrays.copyOf(content, content.length);
    }

    @Override
    public byte[] toBytes() {
        return ByteBuffer.allocate(getEntireLength())
                .put(length)
                .put(content)
                .array();
    }
}
