package jiayu.tls.protocol.handshake;

import java.util.Arrays;
import java.util.List;

public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(0x0000, "", "", ""),
    TLS_RSA_WITH_AES_128_ECB_SHA256(0xFFFE, "RSA", "AES_128_ECB", "SHA256"),
    TLS_RSA_WITH_RSA_1024_ECB_SHA256(0xFFFF, "RSA", "RSA_1024_ECB", "SHA256");

    public static final int BYTES = 2;

    public final short value;
    public final String keyExchangeAlgorithm;
    public final String bulkEncryptionAlgorithm;
    public final String msgAuthenticationAlgorithm;

    CipherSuite(int value, String keyExchangeAlgorithm, String bulkEncryptionAlgorithm, String msgAuthenticationAlgorithm) {
        assert value <= 0xFFFF;
        this.value = (short) value;

        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.bulkEncryptionAlgorithm = bulkEncryptionAlgorithm;
        this.msgAuthenticationAlgorithm = msgAuthenticationAlgorithm;
    }

    public static CipherSuite fromValue(short value) {
        for (CipherSuite cipherSuite : values()) {
            if (cipherSuite.value == value) {
                return cipherSuite;
            }
        }
        return null;
    }

    public static List<CipherSuite> fromValues(short[] values) {
        CipherSuite[] cipherSuites = new CipherSuite[values.length];
        for (int i = 0; i < values.length; i++) {
            cipherSuites[i] = fromValue(values[i]);
        }
        return Arrays.asList(cipherSuites);
    }
}
