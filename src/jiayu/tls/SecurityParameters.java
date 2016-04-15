package jiayu.tls;

public class SecurityParameters {
    private final ConnectionEnd connectionEnd;
    private PRFAlgorithm prfAlgorithm = PRFAlgorithm.TLS_PRF_SHA256;
    private BulkCipherAlgorithm bulkCipherAlgorithm;
    private CipherType cipherType;
    private int encKeyLength;
    private int blockLength;
//    for AEAD
//    private int fixedIVLength;
//    private int recordIVLength;
    private MACAlgorithm macAlgorithm;
    private int macLength;
    private int macKeyLength;
    private CompressionMethod compressionMethod = CompressionMethod.NULL;
    private byte[] masterSecret;
    private byte[] clientRandom;
    private byte[] serverRandom;

    public SecurityParameters(ConnectionEnd connectionEnd) {
        this.connectionEnd = connectionEnd;
    }

    public ConnectionEnd getConnectionEnd() {
        return connectionEnd;
    }

    public PRFAlgorithm getPrfAlgorithm() {
        return prfAlgorithm;
    }

    public BulkCipherAlgorithm getBulkCipherAlgorithm() {
        return bulkCipherAlgorithm;
    }

    public void setCipherSuite(CipherSuite cipherSuite) {
        bulkCipherAlgorithm = cipherSuite.bulkCipherAlgorithm;
        cipherType = bulkCipherAlgorithm.type;
        encKeyLength = bulkCipherAlgorithm.encKeyLength;
        blockLength = bulkCipherAlgorithm.blockLength;
        macAlgorithm = cipherSuite.macAlgorithm;
        macKeyLength = macAlgorithm.macKeyLength;
        macLength = macAlgorithm.macLength;
    }

    public CipherType getCipherType() {
        return cipherType;
    }

    public int getEncKeyLength() {
        return encKeyLength;
    }

    public int getBlockLength() {
        return blockLength;
    }

//    public byte getFixedIVLength() {
//        return fixedIVLength;
//    }
//
//    public byte getRecordIVLength() {
//        return recordIVLength;
//    }

    public MACAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public int getMacLength() {
        return macLength;
    }

    public int getMacKeyLength() {
        return macKeyLength;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }
}
