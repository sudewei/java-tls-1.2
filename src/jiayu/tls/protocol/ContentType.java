package jiayu.tls.protocol;

import java.util.HashMap;

public enum ContentType {
    CHANGE_CIPHER_SPEC(20), ALERT(21), HANDSHAKE(22), APPLICATION_DATA(23);

    private static HashMap<Byte, ContentType> map = new HashMap<>();

    static {
        for (ContentType contentType : values()) {
            map.put(contentType.value, contentType);
        }
    }

    static ContentType valueOf(byte contentType) {
        assert map.get(contentType) != null;
        return map.get(contentType);
    }

    public final byte value;

    ContentType(int value) {
        this.value = (byte) value;
    }
}
