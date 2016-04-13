package jiayu.tls.protocol;

import jiayu.tls.ChannelWriter;
import jiayu.tls.protocol.handshake.Handshake;
import jiayu.tls.protocol.handshake.UIntVector;
import jiayu.tls.protocol.handshake.UnexpectedMessageException;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;

import static jiayu.tls.protocol.ContentType.*;

public class DefaultRecordLayerImpl implements RecordLayer {
    private final SocketChannel sc;
    private final ByteBuffer rcvBuf;
    private final ByteBuffer sndBuf;

    private ContentType leftoversType;
    private ByteQueue inputQueue;

    public DefaultRecordLayerImpl(SocketChannel sc) throws SocketException {
        this.sc = sc;
        rcvBuf = ByteBuffer.allocate(sc.socket().getReceiveBufferSize());
        sndBuf = ByteBuffer.allocate(sc.socket().getSendBufferSize());

        inputQueue = new ByteQueue();
    }

    public ProtocolMessage getNextIncomingMessage() throws IOException, UnexpectedMessageException {
        // invariant: contents of next record or leftoverbytes are a new handshake layer message from the beginning
        ContentType nextMsgType;

        // if inputqueue is empty, fill it with bytes from the next incoming record
        if (inputQueue.isEmpty()) {
            Record nextIncRecord = getNextIncomingRecord();
            nextMsgType = nextIncRecord.getContentType();
            inputQueue.enqueue(nextIncRecord.getContent());
        } else {
            nextMsgType = leftoversType;
        }

        switch (nextMsgType) {
            case CHANGE_CIPHER_SPEC:
                // change cipher specs are only sent one at a time
                // so there should only be one inside a single record
                // and a record cannot be empty
                assert inputQueue.size() == ChangeCipherSpec.BYTES;
                return new Message(CHANGE_CIPHER_SPEC, inputQueue.dequeue(ChangeCipherSpec.BYTES));
            case ALERT:
                // if there are not enough bytes for an alert,
                // we get more bytes from the next incoming record
                while (inputQueue.size() < Alert.BYTES) updateInputQueue(nextMsgType);

                byte[] incAlertContent = inputQueue.dequeue(Alert.BYTES);
                if (!inputQueue.isEmpty()) leftoversType = ALERT;
                return new Message(ALERT, incAlertContent);
            case HANDSHAKE:
                // we need to read the header of the incoming message to find out how long it is
                // but if the entire header has not been received yet,
                // we get more bytes from the next incoming record
                while (inputQueue.size() < Handshake.HEADER_LENGTH) updateInputQueue(nextMsgType);

                byte handshakeType = inputQueue.dequeue();  // ignore handshake type for now
                byte[] length = inputQueue.dequeue(3);  // handshake length field is 3 bytes long
                int incHandshakeLength = UIntVector.btoi(length);

                // if the entire of the incoming handshake is not in the input queue yet,
                // we get more bytes from the next incoming record
                while (inputQueue.size() < incHandshakeLength) updateInputQueue(nextMsgType);

                byte[] incHandshakeContent = inputQueue.dequeue(incHandshakeLength);
                if (!inputQueue.isEmpty()) leftoversType = HANDSHAKE;
                return new Message(HANDSHAKE, incHandshakeContent);
            case APPLICATION_DATA:
                // TODO: 13/04/2016
                return new Message(APPLICATION_DATA, (byte) 0x00);
            default:
                throw new UnexpectedMessageException();
        }
    }

    /**
     * Reads the next incoming Record and adds its contents to the input queue
     *
     * @param nextMsgType The expected content type of the next record
     * @throws IOException If an I/O error occurs
     * @throws UnexpectedMessageException If the content type of the next record is not what was expected
     */
    private void updateInputQueue(ContentType nextMsgType) throws IOException, UnexpectedMessageException {
        Record nextRecord = getNextIncomingRecord();
        if (nextRecord.getContentType() != nextMsgType) throw new UnexpectedMessageException();
        inputQueue.enqueue(nextRecord.getContent());
    }

    private Record getNextIncomingRecord() throws IOException {
        while (rcvBuf.position() < 5) sc.read(rcvBuf);  // read next Record header
        rcvBuf.flip();

        ContentType incRecordType = ContentType.valueOf(rcvBuf.get());  // get next record type
        short incRecordProtocol = rcvBuf.getShort();                    // get next record protocol
        int incRecordLength = rcvBuf.getShort();                        // get next record length

        rcvBuf.compact();

        byte[] incRecordContent = getIncomingRecordContent(incRecordLength);

        return new Record(incRecordType, incRecordProtocol, incRecordContent);
    }

    private byte[] getIncomingRecordContent(int incRecordLength) throws IOException {
        ByteArrayOutputStream incRecordContent = new ByteArrayOutputStream(incRecordLength);
        WritableByteChannel in = Channels.newChannel(incRecordContent);

        int bytesRead = 0;
        while (bytesRead < incRecordLength) {
            if (!rcvBuf.hasRemaining()) sc.read(rcvBuf);
            rcvBuf.flip();
            bytesRead += in.write(rcvBuf);
            rcvBuf.compact();
        }

        return incRecordContent.toByteArray();
    }

    @Override
    public void putNextOutgoingMessage(ProtocolMessage message) throws IOException {
        Record record = new Record(message);
        System.out.println(DatatypeConverter.printHexBinary(record.getBytes()));
        ReadableByteChannel msg = Channels.newChannel(new ByteArrayInputStream(record.getBytes()));
        ChannelWriter.writeBytes(msg, sc, sndBuf);
    }
}
