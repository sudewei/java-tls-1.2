package jiayu.tls.protocol.handshake;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Random {
    static final int BYTES = 32;

    private final int gmtUnixTime;
    private final byte[] randomBytes;

    Random() {
        gmtUnixTime = Math.toIntExact(System.currentTimeMillis() / 1000L);
        randomBytes = new byte[28];
        new SecureRandom().nextBytes(randomBytes);
    }

    private Random(int gmtUnixTime, byte[] randomBytes) {
        this.gmtUnixTime = gmtUnixTime;
        this.randomBytes = randomBytes;
    }

    public byte[] toBytes() {
        return ByteBuffer.allocate(32)
                .putInt(gmtUnixTime)
                .put(randomBytes)
                .array();
    }

    static Random fromBytes(ByteBuffer buf) {
        int gmtUnixTime;
        byte[] randomBytes = new byte[28];

        gmtUnixTime = buf.getInt();
        buf.get(randomBytes);

        return new Random(gmtUnixTime, randomBytes);
    }
}
