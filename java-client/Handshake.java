import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

class Identity {
    public final String name;
    public final Ed25519PrivateKeyParameters priv;
    public final Ed25519PublicKeyParameters pub;

    public Identity(String name) {
        this.name = name;
        SecureRandom random = new SecureRandom();
        this.priv = new Ed25519PrivateKeyParameters(random);
        this.pub = priv.generatePublicKey();
    }
}

class HandshakeResult {
    public final String remoteName;
    public final byte[] remotePub;
    public final byte[] sessionKey;
    public final BufferedReader reader;
    public final BufferedWriter writer;

    public HandshakeResult(String remoteName, byte[] remotePub, byte[] sessionKey,
                           BufferedReader reader, BufferedWriter writer) {
        this.remoteName = remoteName;
        this.remotePub = remotePub;
        this.sessionKey = sessionKey;
        this.reader = reader;
        this.writer = writer;
    }
}

public class Handshake {
    public static HandshakeResult perform(Socket socket, Identity self) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

        SecureRandom random = new SecureRandom();
        X25519PrivateKeyParameters ephPriv = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters ephPub = ephPriv.generatePublicKey();

        byte[] ephPubRaw = ephPub.getEncoded();
        byte[] sig = sign(self.priv, ephPubRaw);

        String hello = "HELLO|" + self.name + "|" +
                Base64.getEncoder().encodeToString(self.pub.getEncoded()) + "|" +
                Base64.getEncoder().encodeToString(ephPubRaw) + "|" +
                Base64.getEncoder().encodeToString(sig) + "\n";
        writer.write(hello);
        writer.flush();

        String line = reader.readLine();
        if (line == null) throw new IOException("remote closed during handshake");
        String[] parts = line.split("\\|");
        if (parts.length != 5 || !parts[0].equals("HELLO")) {
            throw new IOException("invalid HELLO line: " + line);
        }

        String remoteName = parts[1];
        byte[] remotePubRaw = Base64.getDecoder().decode(parts[2]);
        byte[] remoteEphRaw = Base64.getDecoder().decode(parts[3]);
        byte[] remoteSig = Base64.getDecoder().decode(parts[4]);

        Ed25519PublicKeyParameters remotePub = new Ed25519PublicKeyParameters(remotePubRaw, 0);
        if (!verify(remotePub, remoteEphRaw, remoteSig)) {
            throw new IOException("signature verification failed");
        }

        X25519PublicKeyParameters remoteEph = new X25519PublicKeyParameters(remoteEphRaw, 0);
        byte[] shared = new byte[32];
        ephPriv.generateSecret(remoteEph, shared, 0);
        byte[] sessionKey = Crypto.sha256(shared);

        return new HandshakeResult(remoteName, remotePubRaw, sessionKey, reader, writer);
    }

    public static byte[] sign(Ed25519PrivateKeyParameters priv, byte[] msg) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    public static boolean verify(Ed25519PublicKeyParameters pub, byte[] msg, byte[] sig) {
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(sig);
    }
}