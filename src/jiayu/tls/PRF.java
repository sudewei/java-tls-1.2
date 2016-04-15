package jiayu.tls;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public interface PRF {
    static PRF getInstance(PRFAlgorithm prfAlgorithm) throws NoSuchAlgorithmException {
        switch (prfAlgorithm) {
            case TLS_PRF_SHA256:
                return new TLS_PRF_SHA256();
        }
        throw new NoSuchAlgorithmException();
    }

    void init(byte[] key, String label, byte[]... seed) throws InvalidKeyException;

    void init(byte[] key, String label, byte[] seed) throws InvalidKeyException;

    byte[] getBytes(int numBytes);

}
