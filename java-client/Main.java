import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class Main {
    static class App {
        public final Identity identity;
        public final ConcurrentHashMap<String, PeerConn> conns = new ConcurrentHashMap<>();

        public App(Identity identity) {
            this.identity = identity;
        }

        public void addConn(PeerConn pc) throws Exception {
            PeerConn existing = conns.putIfAbsent(pc.name, pc);
            if (existing != null) {
                pc.socket.close();
            }
        }
    }

    public static void connectionLoop(App app, Socket socket) {
        try {
            HandshakeResult hr = Handshake.perform(socket, app.identity);
            PeerConn pc = new PeerConn(hr.remoteName, socket, hr.reader, hr.writer, hr.sessionKey, hr.remotePub);
            app.addConn(pc);
            System.out.println("connected to " + pc.name);

            while (true) {
                String line = pc.reader.readLine();
                if (line == null) {
                    System.out.println("[" + pc.name + "] disconnected");
                    return;
                }
                String[] parts = line.split("\\|");
                if (parts.length != 3 || !parts[0].equals("DATA")) continue;

                byte[] nonce = Base64.getDecoder().decode(parts[1]);
                byte[] ciphertext = Base64.getDecoder().decode(parts[2]);
                byte[] plaintext = Crypto.decrypt(pc.key, nonce, ciphertext);
                Protocol.processPayload(app, pc, new String(plaintext));
            }
        } catch (Exception e) {
            System.out.println("connection error: " + e.getMessage());
        }
    }

    public static void listen(App app, int port) throws Exception {
        ServerSocket server = new ServerSocket();
        server.bind(new InetSocketAddress("127.0.0.1", port));
        System.out.println(app.identity.name + " listening on " + port);

        while (true) {
            Socket socket = server.accept();
            new Thread(() -> connectionLoop(app, socket)).start();
        }
    }

    public static void connectWithRetry(App app, String addr) {
        String[] parts = addr.split(":");
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        for (int i = 0; i < 15; i++) {
            try {
                Socket socket = new Socket(host, port);
                connectionLoop(app, socket);
                return;
            } catch (Exception e) {
                try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
            }
        }
        System.out.println("could not connect to " + addr);
    }

    public static void main(String[] args) throws Exception {
        String name = "java";
        int port = 9003;
        String peers = "";

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--name") && i + 1 < args.length) name = args[++i];
            else if (args[i].equals("--port") && i + 1 < args.length) port = Integer.parseInt(args[++i]);
            else if (args[i].equals("--peers") && i + 1 < args.length) peers = args[++i];
        }

        Protocol.ensureDirs("java-note.txt", "hello from java");
        App app = new App(new Identity(name));

        final int listenPort = port;
        new Thread(() -> {
            try { listen(app, listenPort); }
            catch (Exception e) { System.out.println("listen error: " + e.getMessage()); }
        }).start();

        if (!peers.isBlank()) {
            for (String addr : peers.split(",")) {
                addr = addr.trim();
                if (!addr.isBlank()) {
                    final String a = addr;
                    new Thread(() -> connectWithRetry(app, a)).start();
                }
            }
        }

        Scanner scanner = new Scanner(System.in);
        System.out.println("commands: peers | list <peer> | get <peer> <file> | ping <peer>");
        while (true) {
            String line = scanner.nextLine().trim();
            String[] parts = line.split(" ");
            if (parts[0].equals("peers")) {
                System.out.println("connected peers: " + String.join(", ", app.conns.keySet()));
            } else if (parts[0].equals("ping") && parts.length == 2) {
                PeerConn pc = app.conns.get(parts[1]);
                if (pc == null) System.out.println("unknown peer");
                else Protocol.sendEncrypted(pc, "PING");
            } else if (parts[0].equals("list") && parts.length == 2) {
                PeerConn pc = app.conns.get(parts[1]);
                if (pc == null) System.out.println("unknown peer");
                else Protocol.sendEncrypted(pc, "LIST_REQ");
            } else if (parts[0].equals("get") && parts.length == 3) {
                PeerConn pc = app.conns.get(parts[1]);
                if (pc == null) System.out.println("unknown peer");
                else Protocol.sendEncrypted(pc, "GET_REQ|" + parts[2]);
            }
        }
    }
}