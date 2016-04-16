package jiayu.tls;

public enum BulkCipherAlgorithm {
    NULL(null, "", "", 0, 0, 0),
    AES_128_CBC(CipherType.BLOCK, "AES/CBC/NoPadding", "AES", 16, 16, 16);

    public final CipherType type;
    public final String transformation;
    public final String keySpec;
    public final int encKeyLength;
    public final int ivLength;
    public final int blockSize;

    BulkCipherAlgorithm(CipherType type, String transformation, String keySpec, int encKeyLength, int ivLength, int blockSize) {
        this.type = type;
        this.transformation = transformation;
        this.keySpec = keySpec;
        this.encKeyLength = encKeyLength;
        this.ivLength = ivLength;
        this.blockSize = blockSize;
    }
}
