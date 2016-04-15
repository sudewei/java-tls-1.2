package jiayu.tls;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MasterSecret {
    private final byte[] bytes;

    private MasterSecret(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    public static MasterSecret generateMasterSecret(PremasterSecret premasterSecret, ClientHello clientHello, ServerHello serverHello) throws InvalidKeyException, NoSuchAlgorithmException {
        PRF prf = PRF.getInstance(PRFAlgorithm.TLS_PRF_SHA256);
        prf.init(premasterSecret.getBytes(), "master secret", clientHello.getRandom().toBytes(), serverHello.getRandom().toBytes());
        byte[] bytes = prf.getBytes(48);

        return new MasterSecret(bytes);
    }
}
