package jiayu.tls;

public class SecurityParameters {
    ConnectionEnd connectionEnd;
    PRFAlgorithm prfAlgorithm;
    BulkCipherAlgorithm bulkCipherAlgorithm;
    CipherType cipherType;
    byte encKeyLength;
    byte blockLength;
    byte fixedIVLength;
    byte recordIVLength;
    MACAlgorithm macAlgorithm;
    byte macLength;
    byte macKeyLength;
    CompressionMethod compressionMethod;
    byte[] masterSecret;
    byte[] clientRandom;
    byte[] serverRandom;

    public enum ConnectionEnd {
        CLIENT, SERVER
    }

    public enum PRFAlgorithm {
        TLS_PRF_SHA256
    }

    public enum BulkCipherAlgorithm {
        NULL, RC4, TRIPLE_DES, AES
    }

    public enum CipherType {
        STREAM, BLOCK, AEAD
    }

    public enum MACAlgorithm {
        NULL, HMAC_MD5, HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
    }

    public enum CompressionMethod {
        NULL
    }


}
