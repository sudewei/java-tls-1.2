package jiayu.tls;

public class ServerHelloDone extends Handshake {
    public ServerHelloDone() {
        super(HandshakeType.SERVER_HELLO_DONE);
    }

    @Override
    public byte[] getContent() {
        return createHeader(0);
    }

    public static ServerHelloDone interpret(GenericHandshakeMessage message) throws FatalAlertException {
        if (message.getType() != HandshakeType.SERVER_HELLO_DONE)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);

        if (message.getLength() > 0)
            throw new FatalAlertException(AlertDescription.DECODE_ERROR);

        return new ServerHelloDone();
    }
}
