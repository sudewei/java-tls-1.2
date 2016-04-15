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

public class GenericBlockCipher {
    private final byte[] IV;
    private final byte[] ciphertext;

    /*
    TLS use mac-then-encrypt

    steps for AES 128 CBC encryption
    1. generate a 16 byte IV

    2. pad plaintext to a multiple of 16 bytes
        - padding length - number of bytes used for padding
        - padding - made up of padding-length

    32 (mac length) + 1 (padding_length byte) + x (plaintext length) + padding % 16 = 0

     */

    public GenericBlockCipher(byte[] IV, byte[] ciphertext) {
        this.IV = IV;
        this.ciphertext = ciphertext;
    }

    public byte[] getIV() {
        return IV;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public static GenericBlockCipher encrypt(ConnectionState state, byte[] plaintext) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] key = state.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT
                ? state.getClientWriteKey()
                : state.getServerWriteKey();

        byte[] macWriteKey = state.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT
                ? state.getClientWriteMACKey()
                : state.getServerWriteMACKey();

        System.out.println("plaintext input to mac : + " + DatatypeConverter.printHexBinary(plaintext));

        byte[] mac = MAC(state, macWriteKey, plaintext);

        int macLength = state.getSecurityParameters().getMacLength();
        int blockSize = state.getSecurityParameters().getBlockLength();

        int lengthBefPad = plaintext.length + macLength + 1;
        int minPaddingReq = blockSize - lengthBefPad % blockSize;

        byte[] fragment = new byte[lengthBefPad + minPaddingReq];
        System.arraycopy(plaintext, 0, fragment, 0, plaintext.length);
        System.arraycopy(mac, 0, fragment, plaintext.length, macLength);
        Arrays.fill(fragment, lengthBefPad - 1, fragment.length, (byte) minPaddingReq);

        System.out.println("Content before encryption: " + DatatypeConverter.printHexBinary(fragment));
        System.out.println("MAC: " + DatatypeConverter.printHexBinary(mac));

        assert fragment.length % blockSize == 0;

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        byte[] iv = new byte[state.getSecurityParameters().getBulkCipherAlgorithm().ivLength];
        new SecureRandom().nextBytes(iv);
        System.out.println("Encrypting using IV: " + DatatypeConverter.printHexBinary(iv));
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(fragment);
        System.out.println("Ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));

        return new GenericBlockCipher(iv, ciphertext);
    }

    public static byte[] decrypt(ConnectionState state, GenericBlockCipher blockCipher) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, FatalAlertException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        byte[] iv = blockCipher.getIV();

        System.out.println("Decrypting with IV: " + DatatypeConverter.printHexBinary(iv));
        byte[] writeKey = state.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT
                ? state.getServerWriteKey()
                : state.getClientWriteKey();
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(writeKey, "AES"), new IvParameterSpec(iv));
        assert blockCipher.getCiphertext().length % state.getSecurityParameters().getBulkCipherAlgorithm().blockLength == 0;
        byte[] plainTextMacPadding = cipher.doFinal(blockCipher.getCiphertext());

        System.out.println("Plaintext, mac and padding: " + DatatypeConverter.printHexBinary(plainTextMacPadding));

        byte paddingLength = plainTextMacPadding[plainTextMacPadding.length - 1];
        int plaintextMacLength = plainTextMacPadding.length - paddingLength - 1;
        int macLength = state.getSecurityParameters().getMacAlgorithm().macLength;
        int plaintextLength = plaintextMacLength - macLength;

        for (int i = plaintextMacLength; i < plainTextMacPadding.length; i++)
            if (plainTextMacPadding[i] != paddingLength) throw new FatalAlertException(AlertDescription.BAD_RECORD_MAC);

        byte[] mac = Arrays.copyOfRange(plainTextMacPadding, plaintextLength, plaintextLength + macLength);

        byte[] plaintext = Arrays.copyOfRange(plainTextMacPadding, 0, plaintextLength);

        System.out.println("decrypted plaintext: " + DatatypeConverter.printHexBinary(plaintext));
        System.out.println("decrypted mac: " + DatatypeConverter.printHexBinary(mac));

        byte[] macWriteKey = state.getSecurityParameters().getConnectionEnd() == ConnectionEnd.CLIENT
                ? state.getServerWriteMACKey()
                : state.getClientWriteMACKey();

        byte[] macVerify = MAC(state, macWriteKey, plaintext);
        System.out.println("mac verify   : " + DatatypeConverter.printHexBinary(macVerify));

        if (!Arrays.equals(mac, macVerify)) throw new FatalAlertException(AlertDescription.BAD_RECORD_MAC);

        return plaintext;
    }

    private static byte[] MAC(ConnectionState state, byte[] writeKey, byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(state.getSecurityParameters().getMacAlgorithm().name);
        MACAlgorithm algorithm = state.getSecurityParameters().getMacAlgorithm();
        long sequenceNumber = state.getSequenceNumber();

        mac.init(new SecretKeySpec(writeKey, algorithm.name));
        mac.update(ByteBuffer.allocate(Long.BYTES).putLong(sequenceNumber).array());
        // FIXME: 16/04/2016 hardcoded value
        mac.update(new byte[]{0x03, 0x03});
        mac.update(ByteBuffer.allocate(Short.BYTES).putShort((short) plaintext.length).array());
        mac.update(plaintext);

        return mac.doFinal();
    }
}
