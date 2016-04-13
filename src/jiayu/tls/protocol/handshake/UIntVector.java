package jiayu.tls.protocol.handshake;

public class UIntVector {
    public final byte length;
    public final byte[] bytes;

    public UIntVector(int value) {
        if (value > 0xFF_FFFF) length = 0x04;
        else if (value > 0xFFFF) length = 0x03;
        else if (value > 0xFF) length = 0x02;
        else if (value > 0x00) length = 0x01;
        else length = 0x00;

        this.bytes = itob(value, length);
    }

    public UIntVector(byte[] bytes) {
        assert bytes.length <= 0xFF;
        length = (byte) bytes.length;
        this.bytes = bytes;
    }

    public byte[] toBytes() {
        byte[] bytes = new byte[1 + length];
        bytes[0] = length;
        System.arraycopy(this.bytes, 0, bytes, 1, this.bytes.length);
        return bytes;
    }

    public int getValue() {
        return btoi(bytes);
    }

    public static byte[] itob(int value) {
        return itob(value, 4);
    }

    public static byte[] itob(int value, int size) {
        if (size < 0) throw new IllegalArgumentException("Cannot create array of negative size");

        switch (size) {
            case 0:
                return new byte[0];
            case 1:
                return new byte[]{
                        (byte) (value & 0xFF)};
            case 2:
                return new byte[]{
                        (byte) ((value >>> 8) & 0xFF),
                        (byte) (value & 0xFF)};
            case 3:
                return new byte[]{
                        (byte) ((value >>> 16) & 0xFF),
                        (byte) ((value >>> 8) & 0xFF),
                        (byte) (value & 0xFF)};
            case 4:
                return new byte[]{
                        (byte) ((value >>> 24) & 0xFF),
                        (byte) ((value >>> 16) & 0xFF),
                        (byte) ((value >>> 8) & 0xFF),
                        (byte) (value & 0xFF)};
            default:
                byte[] bytes = new byte[size];
                System.arraycopy(itob(value), 0, bytes, size - 4, 4);
                return bytes;
        }
    }

    public static int btoi(byte[] bytes) {
        switch (bytes.length) {
            case 0:
                return 0;
            case 1:
                return bytes[0] & 0xFF;
            case 2:
                return (bytes[0] & 0xFF) << 8 | bytes[1] & 0xFF;
            case 3:
                return (bytes[0] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | bytes[2] & 0xFF;
            default:
                return (bytes[0] & 0xFF) << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | bytes[3] & 0xFF;
        }
    }
}
