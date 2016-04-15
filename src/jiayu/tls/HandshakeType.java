package jiayu.tls;

import java.util.HashMap;

public enum HandshakeType {
    CLIENT_HELLO(1), SERVER_HELLO(2), CERTIFICATE(11),
    SERVER_HELLO_DONE(14), CLIENT_KEY_EXCHANGE(16), FINISHED(20);

    public static final int BYTES = 1;

    private static HashMap<Byte, HandshakeType> map = new HashMap<>();

    static {
        for (HandshakeType handshakeType : values()) {
            map.put(handshakeType.value, handshakeType);
        }
    }

    static HandshakeType valueOf(byte value) throws FatalAlertException {
        if (map.containsKey(value)) return map.get(value);
        else throw new FatalAlertException(AlertDescription.DECODE_ERROR);
    }

    public final byte value;

    HandshakeType(int value) {
        this.value = (byte) value;
    }
}
