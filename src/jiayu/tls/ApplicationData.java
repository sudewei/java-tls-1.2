package jiayu.tls;

public class ApplicationData implements ProtocolMessage {
    private final byte[] content;

    public ApplicationData(byte[] content) {
        this.content = content;
    }

    @Override
    public ContentType getContentType() {
        return ContentType.APPLICATION_DATA;
    }

    @Override
    public byte[] getContent() {
        return content;
    }
}
