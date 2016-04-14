package jiayu.tls;

interface HandshakeMessage {
    HandshakeType getType();

    int getLength();

    byte[] getContent();

    ClientHello asClientHello() throws FatalAlertException;

    ServerHello asServerHello() throws FatalAlertException;

    Certificate asCertificate() throws FatalAlertException;

    ServerHelloDone asServerHelloDone();
}
