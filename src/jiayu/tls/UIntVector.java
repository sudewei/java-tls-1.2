package jiayu.tls;

public class UIntVector implements ByteVector {
    public static final int LENGTH_BYTES = 1;

    public final byte length;
    public final byte[] bytes;

    public UIntVector(int value) {
        if (value > 0xFF_FFFF) length = 0x04;
        else if (value > 0xFFFF) length = 0x03;
        else if (value > 0xFF) length = 0x02;
        else if (value > 0x00) length = 0x01;
        else length = 0x00;

        this.bytes = UInt.itob(value, length);
    }

    public UIntVector(byte[] bytes) {
        assert bytes.length <= 0xFF;
        length = (byte) bytes.length;
        this.bytes = bytes;
    }

    @Override
    public byte[] toBytes() {
        byte[] bytes = new byte[LENGTH_BYTES + length];
        bytes[0] = length;
        System.arraycopy(this.bytes, 0, bytes, 1, this.bytes.length);
        return bytes;
    }

    public int getValue() {
        return UInt.btoi(bytes);
    }

    @Override
    public int getEntireLength() {
        return LENGTH_BYTES + bytes.length;
    }

    @Override
    public int getLengthFieldLength() {
        return LENGTH_BYTES;
    }

    @Override
    public int getContentLength() {
        return bytes.length;
    }

    @Override
    public byte[] getContent() {
        return bytes;
    }
}
