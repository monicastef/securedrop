import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class ClientTests {
    public static void main(String[] args) throws Exception {
        run("crypto round trip", ClientTests::testCryptoRoundTrip);
        run("metadata round trip", ClientTests::testMetadataRoundTrip);
        run("shared file listing skips metadata", ClientTests::testListSharedFilesSkipsMetadata);
        run("handshake sign verify", ClientTests::testHandshakeSignVerify);
        System.out.println("All Java tests passed.");
    }

    private static void testCryptoRoundTrip() throws Exception {
        byte[] key = Crypto.sha256("java-test-key".getBytes());
        byte[] plaintext = "secure payload".getBytes();

        byte[][] enc = Crypto.encrypt(key, plaintext);
        byte[] decrypted = Crypto.decrypt(key, enc[0], enc[1]);

        assertArrayEquals(plaintext, decrypted, "crypto round trip mismatch");
    }

    private static void testMetadataRoundTrip() throws Exception {
        Files.createDirectories(Path.of("downloads"));
        String filename = "test-" + UUID.randomUUID() + ".txt";

        byte[] originPub = "origin-public-key".getBytes();
        byte[] hash = "hash-bytes".getBytes();
        byte[] sig = "signature-bytes".getBytes();

        try {
            Protocol.saveMetadata(filename, "java", originPub, hash, sig);
            Object[] loaded = Protocol.loadMetadata(filename);

            assertEquals("java", loaded[0], "origin name mismatch");
            assertArrayEquals(originPub, (byte[]) loaded[1], "origin pub mismatch");
            assertArrayEquals(hash, (byte[]) loaded[2], "hash mismatch");
            assertArrayEquals(sig, (byte[]) loaded[3], "signature mismatch");
        } finally {
            Files.deleteIfExists(Protocol.metadataPath(filename));
        }
    }

    private static void testListSharedFilesSkipsMetadata() throws Exception {
        Files.createDirectories(Path.of("shared_files"));
        String filename = "visible-" + UUID.randomUUID() + ".txt";
        Path visible = Path.of("shared_files", filename);
        Path meta = Path.of("shared_files", filename + ".meta");

        try {
            Files.writeString(visible, "hello");
            Files.writeString(meta, "meta");

            List<String> files = Protocol.listSharedFiles();
            if (!files.contains(filename)) {
                throw new AssertionError("shared file list did not contain visible test file");
            }
            if (files.contains(filename + ".meta")) {
                throw new AssertionError("shared file list included metadata file");
            }
        } finally {
            Files.deleteIfExists(visible);
            Files.deleteIfExists(meta);
        }
    }

    private static void testHandshakeSignVerify() throws Exception {
        Identity identity = new Identity("java");
        byte[] message = Base64.getDecoder().decode(Base64.getEncoder().encodeToString("verify me".getBytes()));
        byte[] sig = Handshake.sign(identity.priv, message);

        if (!Handshake.verify(identity.pub, message, sig)) {
            throw new AssertionError("signature verification failed");
        }
    }

    private static void run(String name, CheckedRunnable test) throws Exception {
        try {
            test.run();
            System.out.println("[PASS] " + name);
        } catch (Throwable t) {
            System.out.println("[FAIL] " + name + ": " + t.getMessage());
            if (t instanceof Exception) {
                throw (Exception) t;
            }
            throw new RuntimeException(t);
        }
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (!expected.equals(actual)) {
            throw new AssertionError(message + ": expected " + expected + " but got " + actual);
        }
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual, String message) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
