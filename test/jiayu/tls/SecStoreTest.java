package jiayu.tls;

import jiayu.SecStore;
import jiayu.tls.filetransfer.Metadata;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class SecStoreTest {
    @Test
    public void testSecStore() throws Exception {
        SecStore store = new SecStore();
        store.setDestDir(Paths.get("misc/files/downloaddest"));
        store.bind(4443);
        store.listen();
    }

    private void handle(SecureSocket ss) throws IOException {
        SecureSocketInputStream in = ss.getInputStream();
        OutputStream out = ss.getOutputStream();

        // receive data
        ArrayList<byte[]> ciphertext = new ArrayList<>();

        ByteBuffer incSizeBuf = ByteBuffer.allocate(4);
        in.readFully(incSizeBuf.array());
        int pubKeyLength = incSizeBuf.getInt();
        System.out.println("Public key size: " + pubKeyLength);

        byte[] pubKeyBytes = new byte[pubKeyLength];
        in.readFully(pubKeyBytes);

        System.out.println("public key: " + DatatypeConverter.printBase64Binary(pubKeyBytes));

        incSizeBuf.rewind();
        in.readFully(incSizeBuf.array());
        int incSize = incSizeBuf.getInt();

        int bytesRead = 0;
        while (bytesRead < incSize) {
            byte[] block = new byte[128];
            in.readFully(block);
            bytesRead += 128;
            ciphertext.add(block);
        }

        // decrypt incoming bytes
        ArrayList<byte[]> plaintext = new ArrayList<>();

        Cipher cipher;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyBytes));
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new IOException();
        }

        long startTime = System.currentTimeMillis();
        for (byte[] bytes : ciphertext) {
            try {
                plaintext.add(cipher.doFinal(bytes));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                throw new IOException();
            }
        }
        long endTime = System.currentTimeMillis();
        System.out.println("Decryption time: " + (endTime - startTime));

        // reassemble content
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (byte[] bytes : plaintext) content.write(bytes);

        ByteBuffer buf = ByteBuffer.wrap(content.toByteArray());

        int metadataLength = buf.getInt();
        byte[] metadataBytes = new byte[metadataLength];
        buf.get(metadataBytes);

        Metadata metadata = Metadata.fromBytes(metadataBytes);

        byte[] fileBytes = new byte[metadata.getFilesize()];
        assert buf.remaining() == fileBytes.length;
        buf.get(fileBytes);

        byte[] checksumVerify = Metadata.calculateChecksum(fileBytes);
        if (!Arrays.equals(metadata.getChecksum(), checksumVerify)) {
            throw new IOException();
        } else System.out.println("File verified.");

        String filename = metadata.getFilename();
        Path destDir = Paths.get("misc/files/downloaddest");

        Files.write(destDir.resolve(filename), fileBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

        out.write(1);
        out.flush();
    }

    @Test
    public void testCP1() throws Exception {
        SecStore store = new SecStore();
        store.bind(4443);
        store.listen(this::handle);
    }

    @Test
    public void testGenericReceiveFile() throws Exception {
        SecStore store = new SecStore();
        store.setDestDir(Paths.get("misc/files/downloaddest"));
        store.bind(4443);
        store.listen(store::receiveFile);
    }
}
