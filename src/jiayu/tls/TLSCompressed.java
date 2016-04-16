package jiayu.tls;

public class TLSCompressed extends AbstractRecord {
    TLSCompressed(ContentType contentType, short protocolVersion, byte[] content) {
        super(contentType, protocolVersion, content);
    }
}
