package jiayu.tls;

public enum BulkCipherAlgorithm {
    NULL(null, 0, 0, 0),
    AES_128_CBC(CipherType.BLOCK, 16, 16, 16),
    AES_128_ECB(null, 0, 0, 0),
    RSA_1024(null, 0, 0, 0);

    public final CipherType type;
    public final int encKeyLength;
    public final int ivLength;
    public final int blockLength;

    BulkCipherAlgorithm(CipherType type, int encKeyLength, int ivLength, int blockLength) {
        this.type = type;
        this.encKeyLength = encKeyLength;
        this.ivLength = ivLength;
        this.blockLength = blockLength;
    }
}
