package jiayu;

import jiayu.tls.filetransfer.Metadata;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@SuppressWarnings("Duplicates")
public class Client extends AbstractSecStoreClient {
    private Client() {
        super();
    }

    public boolean upload(byte[] bytes) throws IOException {
        if (!connected) throw new IllegalStateException();

        out.write(bytes);
        out.flush();

        return in.read() == 1;
    }

    public boolean uploadFile(String file) throws IOException {
        return uploadFile(Paths.get(file));
    }

    @Override
    public boolean uploadFile(Path file) throws IOException {
        if (!connected) throw new IllegalStateException();

        if (!Files.exists(file)) throw new IllegalArgumentException("nonexistent file");
        if (!Files.isRegularFile(file)) throw new IllegalArgumentException("cannot upload a directory");

        Metadata metadata = Metadata.get(file);
        byte[] fileData = Files.readAllBytes(file);

        out.write(metadata.getBytes());
        out.write(fileData);
        out.flush();

        return in.read() == 1;
    }

    @Override
    public void disconnect() throws IOException {
        if (!connected) throw new IllegalStateException("not connected");

        in.close();
        out.close();

        socket.close();
    }


//    public boolean uploadFile(Path file) throws IOException {
//        // ensure file exists and is a regular file
//        if (!Files.exists(file)) throw new FileNotFoundException();
//        if (!Files.isRegularFile(file)) throw new IllegalArgumentException();
//
//        // prepare file metadata
//        Metadata md = Metadata.get(file);
//
//        // create FileChannel
//        FileChannel content = FileChannel.open(file);
//
//        // open socket to serverAddress
//        SocketChannel sc = SocketChannel.open(serverAddress);
//
//        // create tcp buffer
//        ByteBuffer buffer = ByteBuffer.allocate(sc.socket().getSendBufferSize());
//
////        // send metadata
////        ChannelWriter.writeBytes(md.toReadableByteChannel(), sc, buffer);
////
////        // send content
////        ChannelWriter.writeBytes(content, sc, buffer);
//
//        // fluent interface implementation
//        ChannelWriter.get(sc, buffer)
//                .write(md.toReadableByteChannel())
//                .write(content);
//
//        // test receive confirmation
//        buffer.clear();
//        sc.read(buffer);
//        buffer.flip();
//        long success = buffer.getLong();
//
//        // close socket
//        sc.close();
//
//        // return true for success
//        return success == UPLOAD_SUCCESS;
//    }

}


