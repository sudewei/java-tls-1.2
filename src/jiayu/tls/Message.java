package jiayu.tls;

public class Message {
    private final ContentType contentType;
    private final byte[] content;

    public Message(ContentType contentType, byte... content) {
        this.contentType = contentType;
        this.content = content;
    }

    public ContentType getContentType() {
        return contentType;
    }

    public byte[] getContent() {
        return content;
    }
}
