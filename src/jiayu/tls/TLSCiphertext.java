package jiayu.tls;

class TLSCiphertext extends AbstractRecord {
    TLSCiphertext(ContentType contentType, short protocolVersion, byte[] content) {
        super(contentType, protocolVersion, content);
    }

    TLSCiphertext(GenericBlockCipher genericBlockCipher) {
        super(genericBlockCipher.getContentType(), PROTOCOL_VERSION, genericBlockCipher.getContent());
    }
}
