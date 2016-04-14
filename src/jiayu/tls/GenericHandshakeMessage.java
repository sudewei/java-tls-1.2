package jiayu.tls;

import java.util.Arrays;

public class GenericHandshakeMessage {
    private final HandshakeType type;
    private final int length;
    private final byte[] content;

    public GenericHandshakeMessage(byte[] content) throws FatalAlertException {
        type = HandshakeType.valueOf(content[0]);
        length = UInt.btoi(Arrays.copyOfRange(content, 1, 4));
        this.content = Arrays.copyOfRange(content, 5, content.length);
    }

    public HandshakeType getType() {
        return type;
    }

    public int getLength() {
        return length;
    }

    public byte[] getContent() {
        return content;
    }

    public ClientHello asClientHello() throws FatalAlertException {
        return ClientHello.interpret(this);
    }

    public ServerHello asServerHello() throws FatalAlertException {
        return ServerHello.interpret(this);
    }

    public Certificate asCertificate() throws FatalAlertException {
        return Certificate.interpret(this);
    }

    public ServerHelloDone asServerHelloDone() throws FatalAlertException {
        return ServerHelloDone.interpret(this);
    }
//
//    ClientKeyExchange asClientKeyExchange() {
//
//    }
//
//    Finished asFinished() {
//
//    }
}
