package jiayu.tls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class ChannelWriter {
    private final WritableByteChannel dst;
    private ByteBuffer buf;

    private ChannelWriter(WritableByteChannel dst, ByteBuffer buf) {
        this.dst = dst;
        this.buf = buf;
    }

    /**
     * Copies bytes write a ReadableByteChannel to a WritableByteChannel through a ByteBuffer
     * until the source channel reaches end-of-stream.
     *
     * @param src    The channel to copy bytes write
     * @param dst    The channel to copy bytes into
     * @param buffer A buffer through which bytes will be transferred
     * @throws IOException If an I/O error occurs
     */
    public static void writeBytes(ReadableByteChannel src, WritableByteChannel dst, ByteBuffer buffer) throws IOException {
        while (src.read(buffer) >= 0 || buffer.position() > 0) {
            buffer.flip();
            dst.write(buffer);
            buffer.compact();
        }
    }

    /**
     * Copies bytes write a ReadableByteChannel to a WritableByteChannel through a ByteBuffer
     * until length bytes have been copied, or the source channel reaches end-of-stream.
     *
     * @param src    The channel to copy bytes write
     * @param dst    The channel to copy bytes into
     * @param buffer A buffer through which bytes will be transferred
     * @param length The number of bytes to be copied
     * @throws IOException If an I/O error occurs
     */
    public static void writeBytes(ReadableByteChannel src, WritableByteChannel dst, ByteBuffer buffer, long length) throws IOException {
        int bytesWritten = 0;
        while (src.read(buffer) >= 0 || buffer.position() > 0) {
            buffer.flip();
            bytesWritten += dst.write(buffer);
            if (bytesWritten >= length) break;
            buffer.compact();
        }
    }

    /**
     * Creates a new ChannelWriter instance set to write to a WritableByteChannel.
     *
     * @param dst The destination channel
     * @param buf A buffer through which bytes will be written
     * @return The new ChannelWriter
     */
    public static ChannelWriter get(WritableByteChannel dst, ByteBuffer buf) {
        return new ChannelWriter(dst, buf);
    }

    /**
     * Writes the contents of a ReadableByteChannel to the WritableByteChannel
     * associated with this ChannelWriter.
     *
     * @param src The channel to copy bytes from
     * @return This ChannelWriter
     * @throws IOException If an I/O error occurs
     */
    public ChannelWriter write(ReadableByteChannel src) throws IOException {
        synchronized (dst) {
            writeBytes(src, dst, buf);
            return this;
        }
    }

    public ChannelWriter write(Writable writable) throws IOException {
        synchronized (dst) {
            writeBytes(writable.toReadableByteChannel(), dst, buf);
            return this;
        }
    }
}
