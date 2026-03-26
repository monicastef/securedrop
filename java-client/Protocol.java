import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

class PeerConn {
    public final String name;
    public final java.net.Socket socket;
    public final BufferedReader reader;
    public final BufferedWriter writer;
    public final byte[] key;
    public final byte[] remotePub;

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
                if (Files.isRegularFile(p)) out.add(p.getFileName().toString());
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
        System.out.println("[" + pc.name + "] wants file '" + filename + "' → auto-accepting");

        Path path = Paths.get("shared_files", filename);
        if (!Files.exists(path)) {
            sendEncrypted(pc, "ERROR|file not found");
            return;
        }

        byte[] data = Files.readAllBytes(path);
        byte[] hash = sha256(data);
        byte[] sig = Handshake.sign(app.identity.priv, hash);

        String msg = "GET_RES|" + filename + "|" +
                Base64.getEncoder().encodeToString(data) + "|" +
                Base64.getEncoder().encodeToString(hash) + "|" +
                Base64.getEncoder().encodeToString(sig);
        sendEncrypted(pc, msg);
        } else if (cmd.equals("GET_RES")) {
            if (parts.length != 5) {
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

            Ed25519PublicKeyParameters remotePub = new Ed25519PublicKeyParameters(pc.remotePub, 0);
            if (!Handshake.verify(remotePub, hash, sig)) {
                System.out.println("[" + pc.name + "] signature verification failed for " + filename);
                return;
            }

            Files.write(Paths.get("downloads", filename), data);
            System.out.println("[" + pc.name + "] downloaded and verified " + filename);
        } else if (cmd.equals("ERROR")) {
            String msg = parts.length > 1 ? parts[1] : "unknown";
            System.out.println("[" + pc.name + "] ERROR: " + msg);
        }
    }
}