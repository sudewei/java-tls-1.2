package jiayu.tls;

public interface ByteVector {
    int getEntireLength();

    int getLengthFieldLength();

    int getContentLength();

    byte[] getContent();

    byte[] toBytes();
}
