package jiayu.tls.protocol;

public class Message implements ProtocolMessage {
    private final ContentType contentType;
    private final byte[] content;

    public Message(ContentType contentType, byte... content) {
        this.contentType = contentType;
        this.content = content;
    }

    @Override
    public ContentType getContentType() {
        return contentType;
    }

    @Override
    public byte[] getContent() {
        return content;
    }
}
