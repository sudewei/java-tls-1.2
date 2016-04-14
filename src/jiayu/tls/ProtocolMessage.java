package jiayu.tls;

public interface ProtocolMessage {
    ContentType getContentType();

    byte[] getContent();
}
