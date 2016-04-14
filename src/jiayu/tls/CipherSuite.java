package jiayu.tls;

import java.util.Arrays;
import java.util.List;

public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(0x0000, "", "", "", 0, 0),
    TLS_RSA_WITH_AES_128_ECB_SHA256(0xFFFE, "RSA", "AES_128_ECB", "SHA256", 128, 256),
    TLS_RSA_WITH_RSA_1024_ECB_SHA256(0xFFFF, "RSA", "RSA_1024_ECB", "SHA256", 1024, 256);

    public static final int BYTES = 2;

    public final short value;
    public final String keyExchangeAlgorithm;
    public final String bulkCipherAlgorithm;
    public final String macAlgorithm;
    public final int encKeyLength;
    public final int macKeyLength;

    CipherSuite(int value, String keyExchangeAlgorithm, String bulkCipherAlgorithm, String macAlgorithm,
                int encKeyLength, int macKeyLength) {
        assert value <= 0xFFFF;
        this.value = (short) value;

        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.bulkCipherAlgorithm = bulkCipherAlgorithm;
        this.macAlgorithm = macAlgorithm;

        this.encKeyLength = encKeyLength;
        this.macKeyLength = macKeyLength;
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
