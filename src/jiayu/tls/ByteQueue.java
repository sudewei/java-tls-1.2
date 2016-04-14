package jiayu.tls;

import java.util.Arrays;
import java.util.NoSuchElementException;

public class ByteQueue {
    private byte[] buffer;

    public ByteQueue() {
        this(0);
    }

    public ByteQueue(int capacity) {
        buffer = new byte[capacity];
    }

    public int size() {
        return buffer.length;
    }

    public boolean isEmpty() {
        return buffer.length == 0;
    }

    public byte element() {
        if (buffer.length < 0) throw new NoSuchElementException();

        return buffer[0];
    }

    public byte peek() {
        if (buffer.length < 1) throw new NoSuchElementException();

        return buffer[0];
    }

    public byte[] peek(int length) {
        if (length > buffer.length) throw new NoSuchElementException();

        return Arrays.copyOfRange(buffer, 0, length);
    }

    public byte[] peek(int length, int offset) {
        if (length + offset > buffer.length) throw new NoSuchElementException();

        byte[] bytes = new byte[length];
        System.arraycopy(buffer, offset, bytes, 0, length);
        return bytes;
    }

    public byte dequeue() {
        if (buffer.length < 1) throw new NoSuchElementException();

        byte b = buffer[0];
        buffer = Arrays.copyOfRange(buffer, 1, buffer.length);
        return b;
    }

    public byte[] dequeue(int length) {
        if (length > buffer.length) throw new NoSuchElementException();

        byte[] bytes = Arrays.copyOfRange(buffer, 0, length);
        buffer = Arrays.copyOfRange(buffer, length, buffer.length);
        return bytes;
    }

    public void enqueue(byte[] bytes) {
        byte[] newBuffer = new byte[buffer.length + bytes.length];

        System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
        System.arraycopy(bytes, 0, newBuffer, buffer.length, bytes.length);

        buffer = newBuffer;
    }
}