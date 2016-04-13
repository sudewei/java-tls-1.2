package jiayu.tls.protocol.handshake;

import jiayu.tls.protocol.ContentType;
import jiayu.tls.protocol.ProtocolMessage;

import java.nio.ByteBuffer;
import java.util.Arrays;

// FIXME: 13/04/2016 IMPLEMENT CERTIFICATE CHAIN LENGTH AND CERTIFICATE LENGTH

public class Certificate extends Handshake {
    private final int length;
    private final byte[] header;

    private final byte[] certificateList;

    public Certificate(byte[] certificateList) {
        super(HandshakeType.CERTIFICATE);

        this.certificateList = certificateList;

        length = certificateList.length;
        header = createHeader(length);
    }

    public byte[] getCertificateList() {
        return Arrays.copyOf(certificateList, certificateList.length);
    }

    private byte[] toBytes() {
        return ByteBuffer.allocate(HEADER_LENGTH + length)
                .put(header)
                .put(certificateList)
                .array();
    }

    public static Certificate interpret(ProtocolMessage message) throws UnexpectedMessageException {
        if (message.getContentType() != ContentType.HANDSHAKE)
            throw new UnexpectedMessageException();

        ByteBuffer content = ByteBuffer.wrap(message.getContent());

        int length = interpretHeader(content, HandshakeType.CERTIFICATE);

        byte[] certificateList = new byte[length];
        content.get(certificateList);

        return new Certificate(certificateList);
    }

    @Override
    public byte[] getContent() {
        return toBytes();
    }
}
