package jiayu.tls;

import java.util.Arrays;

public class GenericHandshakeMessage {
    private final HandshakeType type;
    private final int length;
    private final byte[] content;

    public GenericHandshakeMessage(byte[] content) throws FatalAlertException {
        type = HandshakeType.valueOf(content[0]);
        length = UInt.btoi(Arrays.copyOfRange(content, 1, 4));
        this.content = Arrays.copyOfRange(content, 4, content.length);
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
}
