import java.net.Socket;
import java.io.*;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import javax.crypto.KeyAgreement;
import com.google.gson.Gson;

class Message {
    String IdentityPub;
    String EphemeralPub;
    String Signature;
}

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator edGen = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair id = edGen.generateKeyPair();

        KeyPairGenerator xGen = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair eph = xGen.generateKeyPair();

        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initSign(id.getPrivate());
        sig.update(eph.getPublic().getEncoded());
        byte[] signature = sig.sign();

        Socket socket = new Socket("localhost", 8000);

        Message msg = new Message();
        msg.IdentityPub = Base64.getEncoder().encodeToString(id.getPublic().getEncoded());
        msg.EphemeralPub = Base64.getEncoder().encodeToString(eph.getPublic().getEncoded());
        msg.Signature = Base64.getEncoder().encodeToString(signature);

        Gson gson = new Gson();
        OutputStream out = socket.getOutputStream();
        out.write(gson.toJson(msg).getBytes());

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String resp = in.readLine();

        System.out.println("Java connected & received response");

        socket.close();
    }
}