package jiayu.tls;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ConnectionState {
    private final SecurityParameters securityParameters;
    private byte[] clientWriteMACKey;
    private byte[] serverWriteMACKey;
    private byte[] clientWriteKey;
    private byte[] serverWriteKey;

    private long sequenceNumber;

    public ConnectionState(ConnectionEnd entity) {
        this.securityParameters = new SecurityParameters(entity);
    }

    public void init() throws NoSuchAlgorithmException, InvalidKeyException {
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
