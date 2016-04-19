package jiayu;

import jiayu.tls.SecureServerSocket;
import jiayu.tls.SecureSocket;
import jiayu.tls.SecureSocketInputStream;
import jiayu.tls.filetransfer.Metadata;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
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
import java.util.Scanner;

public class SecStore {
    private static final int CP1 = 1;
    private static final int CP2 = 2;

    private Path destDir;
    private SecureServerSocket sss;

    private boolean listening;
    private boolean interactive;

    public SecStore() throws IOException {
        listening = false;
    }

    public void setServerCert(Path serverCert) throws IOException {
        sss.setServerCert(serverCert);
    }

    public void setServerKey(Path serverKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        sss.setServerKey(serverKey);
    }

    public void setDestDir(Path path) {
        destDir = path;
    }

    public void bind(int port) throws IOException {
        sss = new SecureServerSocket();
        sss.bind(port);
    }

    public void listen() throws IOException {
        receiveFile(sss.acceptSecured());
    }

    public void listen(Handler handler) throws IOException {
        listening = true;
        while (listening) {
            handler.handle(sss.acceptSecured());
        }
    }

    public void receiveBytes(byte[] bytes) {

    }

    public void receiveFile(SecureSocket ss) throws IOException {
        if (destDir == null) throw new IllegalStateException("no destination directory set");

        SecureSocketInputStream in = ss.getInputStream();
        OutputStream out = ss.getOutputStream();

        ByteBuffer buf = ByteBuffer.allocate(1 + Integer.BYTES);
        in.readFully(buf.array());

        int protocol = buf.get();
        int keyLength = buf.getInt();

        byte[] keyBytes = new byte[keyLength];
        in.readFully(keyBytes);

        buf = ByteBuffer.allocate(Integer.BYTES);
        in.readFully(buf.array());
        int dataLength = buf.getInt();

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        byte[] content;

        // decrypt differently based on protocol
        switch (protocol) {
            case CP1:
                content = decryptCP1(in, keyBytes, dataLength);
                break;
            case CP2:
                content = decryptCP2(in, keyBytes, dataLength);
                break;
            default:
                throw new IllegalStateException();
        }

        buf = ByteBuffer.wrap(content);

        int metadataLength = buf.getInt();
        byte[] metadataBytes = new byte[metadataLength];
        buf.get(metadataBytes);

        Metadata metadata = Metadata.fromBytes(metadataBytes);
        System.out.println(String.format("Receiving %s (%d bytes)", metadata.getFilename(), metadata.getFilesize()));

        byte[] fileBytes = new byte[metadata.getFilesize()];
        assert buf.remaining() == fileBytes.length;
        buf.get(fileBytes);

        byte[] checksumVerify = Metadata.calculateChecksum(fileBytes);
        if (!Arrays.equals(metadata.getChecksum(), checksumVerify)) {
            throw new IOException();
        } else System.out.println("File verified.");


        String filename = metadata.getFilename();

        try {
            Files.write(destDir.resolve(filename), fileBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } catch (IOException e) {
            out.write(0);
        }

        out.write(1);
        out.flush();
    }

    private byte[] decryptCP2(SecureSocketInputStream in, byte[] keyBytes, int dataLength) throws IOException {
        byte[] content;

        byte[] toDecrypt = new byte[dataLength];
        in.readFully(toDecrypt);

        SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sks);
            content = cipher.doFinal(toDecrypt);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
        return content;
    }

    private static byte[] decryptCP1(SecureSocketInputStream in, byte[] keyBytes, int dataLength) throws IOException {
        ArrayList<byte[]> ciphertext = new ArrayList<>();
        int bytesRead = 0;
        while (bytesRead < dataLength) {
            byte[] block = new byte[128];
            in.readFully(block);
            bytesRead += 128;
            ciphertext.add(block);
        }

        ArrayList<byte[]> plaintext = new ArrayList<>();

        Cipher cipher;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        long startTime = System.currentTimeMillis();
        for (byte[] bytes : ciphertext) {
            try {
                plaintext.add(cipher.doFinal(bytes));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }
        long endTime = System.currentTimeMillis();
        System.out.println("Decryption time: " + (endTime - startTime));

        // reassemble content
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : plaintext) out.write(bytes);
        return out.toByteArray();
    }

    @FunctionalInterface
    public interface Handler {
        void handle(SecureSocket ss) throws IOException;
    }

    private void startInteractiveMode() {
        Scanner scanner = new Scanner(System.in);
        interactive = true;
        while (interactive) {
            System.out.print("SecStore > ");
            String input = scanner.nextLine();
            parse(input);
        }
    }

    private void parse(String input) {
        String[] tokens = input.split(" ");

        String command = tokens[0];
        String[] args = Arrays.copyOfRange(tokens, 1, tokens.length);

        execute(command, args);
    }

    private void execute(String command, String... args) {
        switch (command) {
            case "set":
                set(args);
                break;
            case "bind":
                int port;
                try {
                    port = Integer.parseInt(args[0]);
                    bind(port);
                    System.out.println("Successfully bound to port " + port);
                } catch (NumberFormatException e) {
                    System.out.println("Invalid port number!");
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "listen":
                try {
                    System.out.println("Server listening...");
                    listen(this::receiveFile);
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "stop":
                try {
                    System.out.println("Trying to close underlying socket... (You may see some error messages.)");
                    sss.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            case "exit":
                interactive = false;
                System.out.println("Exiting SecStore.");
                break;
            default:
                System.out.println("Invalid command!");

        }
    }

    private void set(String... args) {
        switch (args[0]) {
            case "servercert":
                try {
                    setServerCert(Paths.get(args[1]));
                    System.out.println("New server cert set.");
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "serverkey":
                try {
                    setServerKey(Paths.get(args[1]));
                    System.out.println("New server key set.");
                } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "destdir":
                setDestDir(Paths.get(args[1]));
                System.out.println("New destination directory set.");
                break;
            default:
                System.out.println("Invalid command!");
        }
    }

    public static void main(String[] args) {
        try {
            SecStore store = new SecStore();
            System.out.println("Starting SecStore interactive mode");
            store.startInteractiveMode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
