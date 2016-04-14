package jiayu.tls;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

import static jiayu.tls.ContentType.*;

class DefaultRecordLayerImpl implements RecordLayer {
    private final Socket socket;

    private final OutputStream out;
    private final InputStream in;

    public final ByteBuffer rcvBuf;

    private ContentType leftoversType;
    private ByteQueue inputQueue;

    DefaultRecordLayerImpl(Socket socket) throws IOException {
        this.socket = socket;
        out = socket.getOutputStream();
        in = socket.getInputStream();

        rcvBuf = ByteBuffer.allocate(socket.getReceiveBufferSize());

        inputQueue = new ByteQueue();
    }

    public GenericProtocolMessage getNextIncomingMessage() throws IOException, FatalAlertException {
        System.out.println("GETTING NEXT MESSge");

        // invariant: contents of next record or leftoverbytes are a new handshake layer message from the beginning
        ContentType nextMsgType;

        // if inputqueue is empty, fill it with content from the next incoming record
        if (inputQueue.isEmpty()) {
            Record nextIncRecord = getNextIncomingRecord();
            nextMsgType = nextIncRecord.getContentType();
            inputQueue.enqueue(nextIncRecord.getContent());
        } else {
            nextMsgType = leftoversType;
        }

        System.out.println("RECORD LAYER: " + DatatypeConverter.printHexBinary(inputQueue.array()));

        switch (nextMsgType) {
            case CHANGE_CIPHER_SPEC:
                // change cipher specs are only sent one at a time
                // so there should only be one inside a single record
                // and a record cannot be empty

                if (inputQueue.size() != ChangeCipherSpecMessage.BYTES)
                    throw new FatalAlertException(AlertDescription.DECODE_ERROR);

                return new GenericProtocolMessage(CHANGE_CIPHER_SPEC, inputQueue.dequeue(ChangeCipherSpecMessage.BYTES));
            case ALERT:
                // if there are not enough content for an alert,
                // we get more content from the next incoming record
                while (inputQueue.size() < AlertMessage.BYTES) updateInputQueue(ALERT);

                byte[] incAlertContent = inputQueue.dequeue(AlertMessage.BYTES);
                if (!inputQueue.isEmpty()) leftoversType = ALERT;
                return new GenericProtocolMessage(ALERT, incAlertContent);
            case HANDSHAKE:
                // we need to read the header of the incoming message to find out how long it is
                // but if the entire header has not been received yet,
                // we get more content from the next incoming record
                System.out.println("input queue size" + inputQueue.size());
                while (inputQueue.size() < Handshake.HEADER_LENGTH) updateInputQueue(HANDSHAKE);

                byte[] length = inputQueue.peek(3, 1);  // handshake length field is 3 content long
                int incHandshakeLength = UInt.btoi(length);
                System.out.println("incoming handshake length: " + incHandshakeLength);

                // if the entire of the incoming handshake is not in the input queue yet,
                // we get more content from the next incoming record
                while (inputQueue.size() < Handshake.HEADER_LENGTH + incHandshakeLength) updateInputQueue(nextMsgType);

                byte[] incHandshakeContent = inputQueue.dequeue(Handshake.HEADER_LENGTH + incHandshakeLength);
                if (!inputQueue.isEmpty()) leftoversType = HANDSHAKE;
                return new GenericProtocolMessage(HANDSHAKE, incHandshakeContent);
            case APPLICATION_DATA:
                // TODO: 13/04/2016
                return new GenericProtocolMessage(APPLICATION_DATA, new byte[0]);
            default:
                throw new FatalAlertException(AlertDescription.DECODE_ERROR);
        }
    }

    /**
     * Reads the next incoming Record and adds its contents to the input queue
     *
     * @param nextMsgType The expected content type of the next record
     * @throws IOException If an I/O error occurs
     * @throws FatalAlertException If the content type of the next record is not what was expected
     */
    private void updateInputQueue(ContentType nextMsgType) throws IOException, FatalAlertException {
        System.out.println("update input queue");
        Record nextRecord = getNextIncomingRecord();
        if (nextRecord.getContentType() != nextMsgType)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);
        inputQueue.enqueue(nextRecord.getContent());
    }

    private Record getNextIncomingRecord() throws IOException {
        ByteBuffer recordHeader = ByteBuffer.allocate(5);
        in.read(recordHeader.array());
        
        ContentType incRecordType = ContentType.valueOf(recordHeader.get());  // get next record type
        short incRecordProtocol = recordHeader.getShort();                    // get next record protocol
        int incRecordLength = recordHeader.getShort();                        // get next record length

        rcvBuf.compact();

        byte[] incRecordContent = getIncomingRecordContent(incRecordLength);

        System.out.println(DatatypeConverter.printHexBinary(incRecordContent));
        System.out.println(incRecordContent.length);

        return new Record(incRecordType, incRecordProtocol, incRecordContent);
    }

    private byte[] getIncomingRecordContent(int incRecordLength) throws IOException {
        byte[] incRecordContent = new byte[incRecordLength];
        in.read(incRecordContent);
        return incRecordContent;
    }

    @Override
    public void putNextOutgoingMessage(ProtocolMessage message) throws IOException {
        Record record = new Record(message);
        System.out.println(DatatypeConverter.printHexBinary(record.getBytes()));
        out.write(record.getBytes());

    }
}
