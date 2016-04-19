package jiayu.tls;

import java.io.IOException;
import java.io.InputStream;

public class SecureSocketInputStream extends InputStream {
    private final RecordLayer recordLayer;
    private final ByteQueue byteQueue;

    public SecureSocketInputStream(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
        this.byteQueue = new ByteQueue();
    }

    @Override
    public int read() throws IOException {
        if (byteQueue.isEmpty()) {
            try {
                byteQueue.enqueue(recordLayer.getNextIncomingMessage().getContent());
            } catch (FatalAlertException e) {
                e.printStackTrace();
                throw new IOException();
            }
        }
        return byteQueue.dequeue();
    }

    @Override
    public int read(byte[] b) throws IOException {
        if (byteQueue.isEmpty()) {
            try {
                byteQueue.enqueue(recordLayer.getNextIncomingMessage().asApplicationData().getContent());
            } catch (FatalAlertException e) {
                e.printStackTrace();
                throw new IOException();
            }
        }
        int bytesRead = Math.min(b.length, byteQueue.size());
        System.arraycopy(byteQueue.dequeue(bytesRead), 0, b, 0, bytesRead);
        return bytesRead;
    }

    public void readFully(byte[] b) throws IOException {
        while (byteQueue.size() < b.length) {
            try {
                byteQueue.enqueue(recordLayer.getNextIncomingMessage().asApplicationData().getContent());
            } catch (FatalAlertException e) {
                e.printStackTrace();
                throw new IOException();
            }
        }
        System.arraycopy(byteQueue.dequeue(b.length), 0, b, 0, b.length);
    }

    @Override
    public int available() throws IOException {
        return byteQueue.size();
    }
}
