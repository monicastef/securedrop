import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.security.*;
import java.util.Base64;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;

class PeerConn {
    public final String name;
    public final java.net.Socket socket;
    public final BufferedReader reader;
    public final BufferedWriter writer;
    public final byte[] key;
    public byte[] remotePub;

    public PeerConn(String name, java.net.Socket socket, BufferedReader reader,
                    BufferedWriter writer, byte[] key, byte[] remotePub) {
        this.name = name;
        this.socket = socket;
        this.reader = reader;
        this.writer = writer;
        this.key = key;
        this.remotePub = remotePub;
    }
}

public class Protocol {
    public static void ensureDirs(String filename, String content) throws Exception {
        Files.createDirectories(Paths.get("shared_files"));
        Files.createDirectories(Paths.get("downloads"));
        Path p = Paths.get("shared_files", filename);
        if (!Files.exists(p)) {
            Files.writeString(p, content);
        }
    }

    public static List<String> listSharedFiles() throws Exception {
        List<String> out = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get("shared_files"))) {
            for (Path p : stream) {
                if (Files.isRegularFile(p) && !p.getFileName().toString().endsWith(".meta")) {
                    out.add(p.getFileName().toString());
                }
            }
        }
        return out;
    }

    public static void sendEncrypted(PeerConn pc, String payload) throws Exception {
        byte[][] enc = Crypto.encrypt(pc.key, payload.getBytes());
        String line = "DATA|" +
                Base64.getEncoder().encodeToString(enc[0]) + "|" +
                Base64.getEncoder().encodeToString(enc[1]) + "\n";
        pc.writer.write(line);
        pc.writer.flush();
    }

    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public static Path metadataPath(String filename) {
        return Paths.get("downloads", filename + ".meta");
    }

    public static void saveMetadata(String filename, String originName, byte[] originPub, byte[] hash, byte[] sig) throws Exception {
        String content = originName + "|" +
                Base64.getEncoder().encodeToString(originPub) + "|" +
                Base64.getEncoder().encodeToString(hash) + "|" +
                Base64.getEncoder().encodeToString(sig);
        Files.writeString(metadataPath(filename), content);
    }

    public static Object[] loadMetadata(String filename) throws Exception {
        String content = Files.readString(metadataPath(filename)).trim();
        String[] parts = content.split("\\|");
        if (parts.length != 4) throw new IOException("invalid metadata");

        String originName = parts[0];
        byte[] originPub = Base64.getDecoder().decode(parts[1]);
        byte[] hash = Base64.getDecoder().decode(parts[2]);
        byte[] sig = Base64.getDecoder().decode(parts[3]);

        return new Object[]{originName, originPub, hash, sig};
    }

    public static byte[] loadDownload(String filename) throws Exception {
        String content = Files.readString(Paths.get("downloads", filename)).trim();
        String[] parts = content.split("\\|");
        if (parts.length != 2) throw new IOException("invalid stored file");

        byte[] nonce = Base64.getDecoder().decode(parts[0]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[1]);

        return Crypto.decrypt(sha256("local-secret-key".getBytes()), nonce, ciphertext);
    }

    public static void processPayload(Main.App app, PeerConn pc, String payload) throws Exception {
        String[] parts = payload.split("\\|");
        String cmd = parts[0];

        if (cmd.equals("PING")) {
            System.out.println("[" + pc.name + "] PING received");
        } else if (cmd.equals("LIST_REQ")) {
            String joined = String.join(",", listSharedFiles());
            sendEncrypted(pc, "LIST_RES|" + joined);
        } else if (cmd.equals("LIST_RES")) {
            String files = parts.length > 1 ? parts[1] : "";
            System.out.println("[" + pc.name + "] shared files: " + (files.isEmpty() ? "(none)" : files));
        } else if (cmd.equals("GET_REQ")) {
            if (parts.length < 2) {
                sendEncrypted(pc, "ERROR|missing filename");
                return;
            }

            String filename = Paths.get(parts[1]).getFileName().toString();

            // ask user
            System.out.print("[" + pc.name + "] wants file '" + filename + "'. Accept? (y/n): ");

            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
            String resp = console.readLine();

            if (!resp.equalsIgnoreCase("y")) {
                sendEncrypted(pc, "ERROR|request denied");
                return;
            }

            Path sharedPath = Paths.get("shared_files", filename);
            Path downloadPath = Paths.get("downloads", filename);

            byte[] data;
            byte[] hash;
            byte[] sig;
            byte[] originPub;
            String originName;

            if (Files.exists(sharedPath)) {
                data = Files.readAllBytes(sharedPath);

                Path metaPath = Paths.get("shared_files", filename + ".meta");
                if (Files.exists(metaPath)) {
                    String content = Files.readString(metaPath).trim();
                    String[] meta = content.split("\\|");
                    originName = meta[0];
                    originPub = Base64.getDecoder().decode(meta[1]);
                    hash = Base64.getDecoder().decode(meta[2]);
                    sig = Base64.getDecoder().decode(meta[3]);
                } else {
                    hash = sha256(data);
                    sig = Handshake.sign(app.identity.priv, hash);
                    originPub = app.identity.pub.getEncoded();
                    originName = app.identity.name;
                }
            } else if (Files.exists(downloadPath)) {
                data = loadDownload(filename);
                Object[] meta = loadMetadata(filename);
                originName = (String) meta[0];
                originPub = (byte[]) meta[1];
                hash = (byte[]) meta[2];
                sig = (byte[]) meta[3];
            } else {
                sendEncrypted(pc, "ERROR|file not found");
                return;
            }

            String msg = "GET_RES|" + filename + "|" +
                    Base64.getEncoder().encodeToString(data) + "|" +
                    Base64.getEncoder().encodeToString(hash) + "|" +
                    Base64.getEncoder().encodeToString(sig) + "|" +
                    Base64.getEncoder().encodeToString(originPub) + "|" +
                    originName;
            sendEncrypted(pc, msg);
        } else if (cmd.equals("GET_RES")) {
            if (parts.length != 7) {
                System.out.println("[" + pc.name + "] malformed GET_RES");
                return;
            }
            String filename = parts[1];
            byte[] data = Base64.getDecoder().decode(parts[2]);
            byte[] hash = Base64.getDecoder().decode(parts[3]);
            byte[] sig = Base64.getDecoder().decode(parts[4]);

            byte[] actual = sha256(data);
            if (!Arrays.equals(actual, hash)) {
                System.out.println("[" + pc.name + "] hash mismatch for " + filename);
                return;
            }

            byte[] originPubRaw = Base64.getDecoder().decode(parts[5]);
            String originName = parts[6];

            Ed25519PublicKeyParameters originPub = new Ed25519PublicKeyParameters(originPubRaw, 0);

            if (!Handshake.verify(originPub, hash, sig)) {
                System.out.println("[" + pc.name + "] signature verification FAILED for "
                        + filename + " (original: " + originName + ")");
                return;
            }
            byte[][] enc = Crypto.encrypt(sha256("local-secret-key".getBytes()), data);
            String encryptedPayload = Base64.getEncoder().encodeToString(enc[0]) + "|" +
                    Base64.getEncoder().encodeToString(enc[1]);
            Files.writeString(Paths.get("downloads", filename), encryptedPayload);
            saveMetadata(filename, originName, originPubRaw, hash, sig);
            System.out.println("[" + pc.name + "] downloaded and verified " + filename + " (original: " + originName + ")");

        } else if (cmd.equals("KEY_UPDATE")) {
            if (parts.length < 2) {
                System.out.println("[" + pc.name + "] malformed KEY_UPDATE");
                return;
            }

            pc.remotePub = Base64.getDecoder().decode(parts[1]);
            System.out.println("[" + pc.name + "] updated public key");

        } else if (cmd.equals("ERROR")) {
            String msg = parts.length > 1 ? parts[1] : "unknown";
            System.out.println("[" + pc.name + "] ERROR: " + msg);
        }
    }
}
