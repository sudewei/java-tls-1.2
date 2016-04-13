package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import java.nio.ByteBuffer;

public class ServerHelloDone extends Handshake {
    public ServerHelloDone() {
        super(HandshakeType.SERVER_HELLO_DONE);
    }

    @Override
    public byte[] getContent() {
        return createHeader(0);
    }

    public static ServerHelloDone interpret(ProtocolMessage message) throws UnexpectedMessageException {
        if (message.getContentType() != ContentType.HANDSHAKE)
            throw new UnexpectedMessageException();

        ByteBuffer content = ByteBuffer.wrap(message.getContent());

        if (interpretHeader(content, HandshakeType.SERVER_HELLO_DONE) != 0)
            throw new UnexpectedMessageException();

        return new ServerHelloDone();
    }
}
