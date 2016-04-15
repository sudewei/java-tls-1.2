package jiayu.tls;

class TLSCipherText extends AbstractRecord {
    TLSCipherText(ContentType contentType, short protocolVersion, byte[] content) {
        super(contentType, protocolVersion, content);
    }
}
