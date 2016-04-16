package jiayu.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public class SecureSocketOutputStream extends OutputStream {
    private final RecordLayer recordLayer;

    public SecureSocketOutputStream(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
    }

    @Override
    public void write(int b) throws IOException {
        recordLayer.putNextOutgoingMessage(new ApplicationData(new byte[]{(byte) (b & 0xFF)}));
    }

    @Override
    public void write(byte[] b) throws IOException {
        recordLayer.putNextOutgoingMessage(new ApplicationData(b));
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        recordLayer.putNextOutgoingMessage(new ApplicationData(Arrays.copyOfRange(b, off, off + len)));
    }

    @Override
    public void close() throws IOException {
        recordLayer.close();
    }
}
