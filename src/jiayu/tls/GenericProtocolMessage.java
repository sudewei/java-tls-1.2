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
        if (contentType != ContentType.CHANGE_CIPHER_SPEC)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        return new ChangeCipherSpecMessage(content);
    }

    public AlertMessage asAlertMessage() throws FatalAlertException {
        if (contentType != ContentType.ALERT)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        return new AlertMessage(content);
    }

    public HandshakeMessage asHandshakeMessage(HandshakeType type) throws FatalAlertException {
        if (contentType != ContentType.HANDSHAKE)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        GenericHandshakeMessage handshake = new GenericHandshakeMessage(content);

        switch (type) {
            case CLIENT_HELLO:
                return ClientHello.interpret(handshake);
            case SERVER_HELLO:
                return ServerHello.interpret(handshake);
            case CERTIFICATE:
                return Certificate.interpret(handshake);
            case SERVER_HELLO_DONE:
                return ServerHelloDone.interpret(handshake);
            case CLIENT_KEY_EXCHANGE:
                return ClientKeyExchange.interpret(handshake);
            case FINISHED:
                // TODO: 15/04/2016
                return Finished.interpret(handshake);
            default:
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
        }
    }

    public ApplicationData asApplicationData() throws FatalAlertException {
        if (contentType != ContentType.APPLICATION_DATA)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        return new ApplicationData(content);
    }
}
