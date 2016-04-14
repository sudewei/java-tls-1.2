package jiayu.tls;

public class GenericProtocolMessage implements ProtocolMessage {
    private final ContentType contentType;
    private final byte[] content;

    public GenericProtocolMessage(ContentType contentType, byte[] content) {
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

    public ChangeCipherSpecMessage asChangeCipherSpecMessage() throws FatalAlertException {
        return new ChangeCipherSpecMessage(content);
    }

    public AlertMessage asAlertMessage() throws FatalAlertException {
        return new AlertMessage(content);
    }

    public GenericHandshakeMessage asHandshakeMessage() throws FatalAlertException {
        return new GenericHandshakeMessage(content);
    }

}
