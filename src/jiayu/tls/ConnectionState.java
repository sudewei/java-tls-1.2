package jiayu.tls;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ConnectionState {
    private SecurityParameters securityParameters;

    private CompressionMethod compressionAlgorithm;
    private BulkCipherAlgorithm encryptionAlgorithm;
    private MACAlgorithm macAlgorithm;

    private byte[] clientWriteMACKey;
    private byte[] serverWriteMACKey;
    private byte[] clientWriteKey;
    private byte[] serverWriteKey;

    private long sequenceNumber;

    public ConnectionState() {
        compressionAlgorithm = null;
        encryptionAlgorithm = null;
        macAlgorithm = null;
    }

    public void init(SecurityParameters securityParameters) throws NoSuchAlgorithmException, InvalidKeyException {
        this.securityParameters = securityParameters;
        if (securityParameters.getCipherSuite() == CipherSuite.TLS_NULL_WITH_NULL_NULL) return;

        this.compressionAlgorithm = securityParameters.getCompressionMethod();
        this.encryptionAlgorithm = securityParameters.getBulkCipherAlgorithm();
        this.macAlgorithm = securityParameters.getMacAlgorithm();

        PRFAlgorithm prfAlgorithm = securityParameters.getPrfAlgorithm();
        byte[] masterSecret = securityParameters.getMasterSecret();
        byte[] serverRandom = securityParameters.getServerRandom();
        byte[] clientRandom = securityParameters.getClientRandom();
        int macKeyLength = securityParameters.getMacKeyLength();
        int encKeyLength = securityParameters.getEncKeyLength();

        PRF prf = PRF.getInstance(prfAlgorithm);
        prf.init(masterSecret, "key expansion", serverRandom, clientRandom);
        clientWriteMACKey = prf.getBytes(macKeyLength);
        serverWriteMACKey = prf.getBytes(macKeyLength);
        clientWriteKey = prf.getBytes(encKeyLength);
        serverWriteKey = prf.getBytes(encKeyLength);

        sequenceNumber = 0;
    }

    public CompressionMethod getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public BulkCipherAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public MACAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public SecurityParameters getSecurityParameters() {
        return securityParameters;
    }

    public byte[] getClientWriteMACKey() {
        return clientWriteMACKey;
    }

    public byte[] getServerWriteMACKey() {
        return serverWriteMACKey;
    }

    public byte[] getClientWriteKey() {
        return clientWriteKey;
    }

    public byte[] getServerWriteKey() {
        return serverWriteKey;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public void incrementSequenceNumber() {
        sequenceNumber++;
    }
}
