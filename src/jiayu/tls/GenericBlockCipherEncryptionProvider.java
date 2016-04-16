package jiayu.tls;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

class GenericBlockCipherEncryptionProvider {
    private GenericBlockCipherEncryptionProvider() {

    }

    static GenericBlockCipher encrypt(ConnectionState writeState, ProtocolMessage message) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        assert writeState.getSecurityParameters().getCipherSuite() != CipherSuite.TLS_NULL_WITH_NULL_NULL;

        BulkCipherAlgorithm algorithm = writeState.getEncryptionAlgorithm();
        int ivLength = algorithm.ivLength;
        int blockSize = algorithm.blockSize;
        MACAlgorithm macAlgorithm = writeState.getMacAlgorithm();
        int macLength = macAlgorithm.macLength;

        long seqNum = writeState.getSequenceNumber();

        // when encrypting, the write key corresponding to the connection end is used
        byte[] encKey = writeState.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT ?
                writeState.getClientWriteKey()
                : writeState.getServerWriteKey();
        byte[] macKey = writeState.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT
                ? writeState.getClientWriteMACKey()
                : writeState.getServerWriteMACKey();

        TLSPlaintext tlsPlaintext = new TLSPlaintext(message);
        byte[] plaintext = tlsPlaintext.getContent();

        // tls uses mac-then-encrypt and includes a sequence number and the TLSPlaintext type, version and length
        byte[] plaintextMAC = MAC(macAlgorithm, macKey, seqNum, tlsPlaintext);

        // a GenericBlockCipher encrypts the plaintext mac, plaintext, padding and padding_length byte
        // calculate minimum padding required
        int lengthBefPad = plaintext.length + macLength + 1;
        int minPaddingReq = blockSize - lengthBefPad % blockSize;

        // randomise the padding length up to the max length of 255
        int extraPadMultiples = (255 - minPaddingReq) / blockSize;
        int padAmount = minPaddingReq + new SecureRandom().nextInt(extraPadMultiples) * blockSize;
        System.out.println("padding length: " + padAmount);

        assert padAmount < 255;
        assert (lengthBefPad + padAmount) % blockSize == 0;

        ByteBuffer fragment = ByteBuffer.allocate(lengthBefPad + padAmount);
        fragment.put(plaintext)
                .put(plaintextMAC);
        Arrays.fill(fragment.array(), lengthBefPad - 1, fragment.capacity(), (byte) padAmount);

        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);
        System.out.println("Encrypting using IV: " + DatatypeConverter.printHexBinary(iv));
        Cipher cipher = Cipher.getInstance(algorithm.transformation);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, algorithm.keySpec), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(fragment.array());
        System.out.println("Ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));

        writeState.incrementSequenceNumber();
        return new GenericBlockCipher(message.getContentType(), iv, ciphertext);
    }

    static byte[] decrypt(ConnectionState readState, TLSCiphertext tlsCiphertext) throws FatalAlertException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        assert readState.getSecurityParameters().getCipherSuite() != CipherSuite.TLS_NULL_WITH_NULL_NULL;

        BulkCipherAlgorithm algorithm = readState.getEncryptionAlgorithm();
        int ivLength = algorithm.ivLength;
        MACAlgorithm macAlgorithm = readState.getMacAlgorithm();
        int macLength = macAlgorithm.macLength;

        long seqNum = readState.getSequenceNumber();

        // when decrypting, the write key corresponding to the opposite connection end is used
        byte[] encKey = readState.getSecurityParameters().getConnectionEnd() != ConnectionEnd.CLIENT
                ? readState.getClientWriteKey()
                : readState.getServerWriteKey();
        byte[] macKey = readState.getSecurityParameters().getConnectionEnd() != ConnectionEnd.CLIENT
                ? readState.getClientWriteMACKey()
                : readState.getServerWriteMACKey();

        byte[] iv = Arrays.copyOf(tlsCiphertext.getContent(), ivLength);
        System.out.println("Decrypting with IV: " + DatatypeConverter.printHexBinary(iv));
        byte[] cipherText = Arrays.copyOfRange(tlsCiphertext.getContent(), ivLength, tlsCiphertext.getContent().length);

        Cipher cipher = Cipher.getInstance(algorithm.transformation);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, algorithm.keySpec), new IvParameterSpec(iv));

        // the decrypted fragment is comprised of the plaintext, the plaintext mac and the padding
        byte[] fragment = cipher.doFinal(cipherText);

        int paddingLength = fragment[fragment.length - 1] & 0xFF;
        System.out.println("padding length: " + paddingLength);
        int plaintextLength = fragment.length - paddingLength - macLength - 1;

        for (int i = 0; i < paddingLength; i++) {
            if ((fragment[plaintextLength + macLength + i] & 0xFF) != paddingLength)
                throw new FatalAlertException(AlertDescription.BAD_RECORD_MAC);
        }

        byte[] plaintext = Arrays.copyOf(fragment, plaintextLength);
        byte[] mac = Arrays.copyOfRange(fragment, plaintextLength, plaintextLength + macLength);

        TLSPlaintext tlsPlaintext = new TLSPlaintext(tlsCiphertext.getContentType(), tlsCiphertext.getProtocolVersion(), plaintext);
        byte[] macVerify = MAC(macAlgorithm, macKey, seqNum, tlsPlaintext);

        if (!Arrays.equals(mac, macVerify)) throw new FatalAlertException(AlertDescription.BAD_RECORD_MAC);

        readState.incrementSequenceNumber();
        return plaintext;
    }

    private static byte[] MAC(MACAlgorithm algorithm, byte[] macWriteKey, long seqNum, TLSPlaintext tlsPlaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.name);
        mac.init(new SecretKeySpec(macWriteKey, algorithm.name));

        mac.update(ByteBuffer.allocate(Long.BYTES).putLong(seqNum).array());
        mac.update(tlsPlaintext.getBytes());

        return mac.doFinal();
    }
}
