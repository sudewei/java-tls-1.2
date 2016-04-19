package jiayu;

import jiayu.tls.UInt;
import jiayu.tls.filetransfer.Metadata;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class CP1Client extends AbstractSecStoreClient {
    public static void main(String[] args) {
        try {
            SecStoreClient client = SecStoreClient.getInstance("CP1");
            client.connect("localhost", 4443);
            if (client.uploadFile("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\files\\1MB")) {
                System.out.println("Upload success!");
            } else {
                System.out.println("Upload failed.");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public CP1Client() {
        super();
    }

    @Override
    public boolean uploadFile(Path file) throws IOException {
        // prepare the data by RSA encrypting it in 117 byte chunks
        Metadata metadata = Metadata.get(file);
        byte[] plaintext = Files.readAllBytes(file);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(metadata.getBytes());
        baos.write(plaintext);

        ByteBuffer buf = ByteBuffer.wrap(baos.toByteArray());

        ArrayList<byte[]> plaintextBlocks = new ArrayList<>();
        while (buf.remaining() > 117) {
            byte[] temp = new byte[117];
            buf.get(temp);
            plaintextBlocks.add(temp);
        }
        byte[] temp = new byte[buf.remaining()];
        buf.get(temp);
        plaintextBlocks.add(temp);

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        Object[] plaintextBlocksArray = plaintextBlocks.toArray();
        byte[][] ciphertextBlocksArray = new byte[plaintextBlocksArray.length][];

        System.out.println("encrypting data...");

        encrypt(privateKey, plaintextBlocksArray, ciphertextBlocksArray, 4);
        System.out.println("finished encrypting");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] pubKeyBytes = publicKey.getEncoded();

        output.write(UInt.itob(pubKeyBytes.length));
        output.write(pubKeyBytes);

        output.write(UInt.itob(plaintextBlocks.size()));

        for (byte[] bytes : ciphertextBlocksArray) {
            output.write(bytes);
        }

        out.write(output.toByteArray());
        return in.read() == 1;
    }

    private void encrypt(Key privateKey, Object[] src, byte[][] dst, int numThreads) {
        final int numBlocks = src.length;
        final int step = numBlocks / 100;
        final AtomicInteger counter = new AtomicInteger(0);

        Thread[] threads = new Thread[numThreads];
        for (int i = 0; i < numThreads; i++) {
            threads[i] = new Thread(new EncryptionWorker(privateKey, src, dst, numThreads, i, counter));
            threads[i].start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }
    }

    private class EncryptionWorker implements Runnable {
        final Key privateKey;
        final Object[] src;
        final byte[][] dst;
        final int numThreads;
        final int index;
        final AtomicInteger counter;
        final int step;

        final Cipher cipher;

        EncryptionWorker(Key privateKey, Object[] src, byte[][] dst, int numThreads, int index, AtomicInteger counter) {
            this.privateKey = privateKey;
            this.src = src;
            this.dst = dst;
            this.numThreads = numThreads;
            this.index = index;
            this.counter = counter;
            step = src.length / 10;

            try {
                this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }

        @Override
        public void run() {
            for (int i = 0; ; i++) {
                int current = i * numThreads + index;
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    dst[current] = cipher.doFinal((byte[]) src[current]);
                    counter.getAndIncrement();
                    if (counter.compareAndSet(step, 0)) {
                        System.out.printf("=");
                    }

                } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                    throw new RuntimeException();
                }
                if (current + numThreads >= src.length) break;
            }
        }
    }

}
