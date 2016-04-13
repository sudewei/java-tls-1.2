package jiayu.tls.protocol;

public interface ProtocolMessage {
    ContentType getContentType();

    byte[] getContent();
}
