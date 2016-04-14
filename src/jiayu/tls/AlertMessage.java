package jiayu.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;

public class AlertMessage implements ProtocolMessage {
    public static final int BYTES = 2;

    private final AlertLevel level;
    private final AlertDescription description;

    public AlertMessage(byte[] content) throws FatalAlertException {
        level = AlertLevel.valueOf(content[0]);
        description = AlertDescription.valueOf(content[1]);
    }

    private AlertMessage(AlertLevel level, AlertDescription description) {
        this.level = level;
        this.description = description;
    }

    public byte[] toBytes() {
        return new byte[]{level.value, description.value};
    }

    public static AlertMessage fatal(AlertDescription desc) {
        return new AlertMessage(AlertLevel.FATAL, desc);
    }

    public static AlertMessage unexpectedMessageAlert() {
        return new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @Override
    public ContentType getContentType() {
        return ContentType.ALERT;
    }

    @Override
    public byte[] getContent() {
        return new byte[]{level.value, description.value};
    }

    private Record toRecord() {
        return new Record(this);
    }

    void send(SocketChannel sc) throws IOException {
        Record record = toRecord();
        ChannelWriter.writeBytes(
                Channels.newChannel(new ByteArrayInputStream(record.getBytes())),
                sc,
                ByteBuffer.allocate(record.getLength())
        );

    }
}
