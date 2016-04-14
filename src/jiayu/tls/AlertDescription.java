package jiayu.tls;

import java.util.HashMap;

public enum AlertDescription {
    CLOSE_NOTIFY(0), UNEXPECTED_MESSAGE(10), HANDSHAKE_FAILURE(40), BAD_CERTIFICATE(42),
    CERTIFICATE_EXPIRED(45), DECODE_ERROR(50), DECRYPT_ERROR(51), INTERNAL_ERROR(80);

    private static HashMap<Byte, AlertDescription> map;

    static {
        for (AlertDescription desc : values()) map.put(desc.value, desc);
    }

    public final byte value;

    AlertDescription(int value) {
        assert value <= 0xFF;
        this.value = (byte) value;
    }

    public static AlertDescription valueOf(byte value) throws FatalAlertException {
        if (map.containsKey(value)) return map.get(value);
        else throw new FatalAlertException(DECODE_ERROR);
    }
}
