package jiayu.tls;

import java.util.List;

public interface Vector<T> extends ByteVector {
    /*
    What will I be interested in from a vector?


    The length of its length field

    Its total length in content

    The length of its contents

    A list of its contents



    Considerations: vectors of vectors: non-constant element size



    Some vectors I have to implement:

    session_id (1 byte of length, byte content)

    cipher_suites (2 content of length, 2 content per element)

    compression_methods (1 byte of length, 1 byte per element)

    extensions (2 content of length, contains extension_data)

        extension_data (2 content of length, byte content)

    certificate_list (3 content of length, contains asn1certs)

    asn1cert (3 content of length, byte content)
     */

    List<T> getContents();
}