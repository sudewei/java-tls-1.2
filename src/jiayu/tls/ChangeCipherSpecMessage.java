package jiayu.tls;

import java.util.Arrays;

public class ChangeCipherSpecMessage implements ProtocolMessage {
    public static final int BYTES = 1;

    private static final byte[] CHANGE_CIPHER_SPEC = new byte[]{0x01};

    public byte[] toBytes() {
        return CHANGE_CIPHER_SPEC;
    }

    public ChangeCipherSpecMessage() {
    }

    ChangeCipherSpecMessage(byte[] content) throws FatalAlertException {
        if (!Arrays.equals(content, CHANGE_CIPHER_SPEC)) {
            throw new FatalAlertException(AlertDescription.DECODE_ERROR);
        }
    }

    static ChangeCipherSpecMessage createFrom(Record record) {
        return new ChangeCipherSpecMessage();
    }

    @Override
    public ContentType getContentType() {
        return ContentType.CHANGE_CIPHER_SPEC;
    }

    @Override
    public byte[] getContent() {
        return CHANGE_CIPHER_SPEC;
    }
}
