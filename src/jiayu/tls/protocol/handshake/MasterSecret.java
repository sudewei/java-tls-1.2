package jiayu.tls.protocol.handshake;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MasterSecret {
    byte[] bytes;

    private MasterSecret(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    public static MasterSecret generateMasterSecret(PremasterSecret premasterSecret, ClientHello clientHello, ServerHello serverHello) throws InvalidKeyException, NoSuchAlgorithmException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(premasterSecret.getBytes(), "HmacSHA256"));
        hmac.update("master secret".getBytes());
        hmac.update(clientHello.getRandom().toBytes());
        hmac.update(serverHello.getRandom().toBytes());
        byte[] A1 = hmac.doFinal();
        byte[] A2 = hmac.doFinal(A1);
        byte[] bytes = ByteBuffer.allocate(48).put(A1).put(A2, 0, 16).array();
        return new MasterSecret(bytes);
    }
}
