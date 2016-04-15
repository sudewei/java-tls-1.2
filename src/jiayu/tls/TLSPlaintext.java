package jiayu.tls;

class TLSPlaintext extends AbstractRecord {
    TLSPlaintext(ContentType contentType, short protocolVersion, byte[] content) {
        super(contentType, protocolVersion, content);
    }

    TLSPlaintext(ProtocolMessage message) {
        this(message.getContentType(), PROTOCOL_VERSION, message.getContent());
    }
}
