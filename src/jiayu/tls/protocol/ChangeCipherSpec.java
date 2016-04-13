package jiayu.tls.protocol;

import jiayu.tls.protocol.handshake.UnexpectedMessageException;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;

public class ChangeCipherSpec implements ProtocolMessage {
    public static final int BYTES = 1;
    public static final byte[] CHANGE_CIPHER_SPEC = new byte[]{0x01};

    public byte[] toBytes() {
        return CHANGE_CIPHER_SPEC;
    }

    static ChangeCipherSpec createFrom(Record record) {
        return new ChangeCipherSpec();
    }

    public static ChangeCipherSpec tryToReadFrom(ReadableByteChannel src) throws IOException, UnexpectedMessageException {
        Record record = Record.readFrom(src);

        if (record.getContentType() != ContentType.CHANGE_CIPHER_SPEC) {
            throw new UnexpectedMessageException();
        }

        if (!Arrays.equals(record.getContent(), CHANGE_CIPHER_SPEC)) {
            throw new UnexpectedMessageException();
        }

        return createFrom(record);
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
