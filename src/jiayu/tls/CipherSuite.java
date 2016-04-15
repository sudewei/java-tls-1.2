package jiayu.tls;

import java.util.Arrays;
import java.util.List;

import static jiayu.tls.BulkCipherAlgorithm.AES_128_CBC;
import static jiayu.tls.BulkCipherAlgorithm.AES_128_ECB;
import static jiayu.tls.KeyExchangeAlgorithm.RSA;
import static jiayu.tls.MACAlgorithm.HMAC_SHA256;
import static jiayu.tls.PRFAlgorithm.TLS_PRF_SHA256;



public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(0x0000, null, null, null, null),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x002F, TLS_PRF_SHA256, RSA, AES_128_CBC, HMAC_SHA256),
    TLS_RSA_WITH_AES_128_ECB_SHA256(0xFFFE, TLS_PRF_SHA256, RSA, AES_128_ECB, HMAC_SHA256),
    TLS_RSA_WITH_RSA_1024_ECB_SHA256(0xFFFF, TLS_PRF_SHA256, RSA, BulkCipherAlgorithm.RSA_1024, HMAC_SHA256);

    public static final int BYTES = 2;

    public final short value;
    public final PRFAlgorithm prfAlgorithm;
    public final KeyExchangeAlgorithm keyExchangeAlgorithm;
    public final BulkCipherAlgorithm bulkCipherAlgorithm;
    public final MACAlgorithm macAlgorithm;

    CipherSuite(int value,
                PRFAlgorithm prfAlgorithm,
                KeyExchangeAlgorithm keyExchangeAlgorithm,
                BulkCipherAlgorithm bulkCipherAlgorithm,
                MACAlgorithm macAlgorithm) {
        this.value = (short) value;

        this.prfAlgorithm = prfAlgorithm;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.bulkCipherAlgorithm = bulkCipherAlgorithm;
        this.macAlgorithm = macAlgorithm;
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
