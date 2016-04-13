package jiayu.tls.protocol.handshake;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class PremasterSecret {
    private byte[] bytes;

    public PremasterSecret(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static PremasterSecret newRSAPremasterSecret(short clientVersion) {
        byte[] random = new byte[46];
        new SecureRandom().nextBytes(random);

        byte[] bytes = ByteBuffer.allocate(48)
                .putShort(clientVersion)
                .put(random)
                .array();

        return new PremasterSecret(bytes);
    }

    public byte[] getEncryptedBytes(X509Certificate serverCert) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverCert);
        return cipher.doFinal(this.bytes);
    }

    public void decrypt(Key serverKey, short clientVersion) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] random = new byte[46];
        new SecureRandom().nextBytes(random);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, serverKey);
        bytes = cipher.doFinal(bytes);

        // as described in https://tools.ietf.org/html/rfc5246#ref-KPR03
        byte[] clientVersionBytes = ByteBuffer.allocate(2).putShort(clientVersion).array();
        byte[] bytes = new byte[48];
        System.arraycopy(clientVersionBytes, 0, bytes, 0, 2);
        if (bytes.length != 48) {
            System.arraycopy(random, 0, bytes, 2, 46);
        } else {
            System.arraycopy(this.bytes, 2, bytes, 2, 46);
        }
        this.bytes = bytes;
    }


    byte[] toBytes() {
        return bytes;
    }
}
