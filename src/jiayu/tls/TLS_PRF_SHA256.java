package jiayu.tls;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class TLS_PRF_SHA256 implements PRF {
    public static final int OUTPUT_LENGTH = 32;

    private static final String ALGORITHM = "HmacSHA256";

    private final Mac hmac;
    private boolean initialised;
    private byte[] prevOutput;
    private byte[] output;

    TLS_PRF_SHA256() throws NoSuchAlgorithmException {
        hmac = Mac.getInstance(ALGORITHM);
        initialised = false;
        prevOutput = null;

    }

    @Override
    public void init(byte[] key, String label, byte[] seed) throws InvalidKeyException {
        hmac.init(new SecretKeySpec(key, ALGORITHM));
        hmac.update(label.getBytes());
        hmac.update(seed);

        initialised = true;
    }

    @Override
    public void init(byte[] key, String label, byte[]... seed) throws InvalidKeyException {
        hmac.init(new SecretKeySpec(key, ALGORITHM));
        hmac.update(label.getBytes());
        for (byte[] bytes : seed) hmac.update(bytes);

        initialised = true;
    }


    @Override
    public byte[] getBytes(int numBytes) {
        if (!initialised) throw new IllegalStateException();

        ByteQueue output = new ByteQueue();

        while (output.size() < numBytes) {
            if (prevOutput == null) {
                byte[] b = hmac.doFinal();
                output.enqueue(b);
                prevOutput = b;
            } else {
                byte[] b = hmac.doFinal(prevOutput);
                output.enqueue(b);
                prevOutput = b;
            }
        }

        return output.dequeue(numBytes);
    }
}
