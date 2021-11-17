package li.power.app.wearos.teslanak.nfc;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import li.power.app.wearos.teslanak.MainActivity;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/*
 *
 * Ref: https://gist.github.com/darconeous/2cd2de11148e3a75685940158bddf933
 *
 * */
public class TeslaNAKService extends HostApduService {
    /* Card commands we support. */
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x04;
    private static final byte INS_AUTHENTICATE = (byte) 0x11;
    private static final byte INS_GET_CARD_INFO = (byte) 0x14;

    private static final byte[] SW_SUCCESS = new byte[]{(byte) 0x90, 0x00};
    private static final byte[] SW_CLA_NOT_SUPPORTED = new byte[]{(byte) 0x6E, (byte) 0x00};
    private static final byte[] SW_INS_NOT_SUPPORTED = new byte[]{(byte) 0x6D, (byte) 0x00};
    private static final byte[] SW_UNKNOWN = new byte[]{(byte) 0x6F, (byte) 0x00};
    private static final byte[] SW_WRONG_LENGTH = new byte[]{(byte) 0x67, (byte) 0x00};

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "tesla_nak";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String CURVE = "secp256r1";

    private KeyStore keyStore;
    private final SecureRandom random = new SecureRandom();
    private SharedPreferences sharedPreferences;


    @Override
    public void onCreate() {
        setupBouncyCastle();
        sharedPreferences = getSharedPreferences(KEY_ALIAS, MODE_PRIVATE);
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                Toast.makeText(this, "Please open app to generate the keypair", Toast.LENGTH_LONG).show();
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Toast.makeText(this, "Error initializing keystore", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }

        super.onCreate();
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        byte[] resp = process(commandApdu);
        Log.d("Resp", Hex.toHexString(resp));
        return resp;

    }

    private byte[] process(byte[] commandApdu) {

        CommandAPDU apdu = new CommandAPDU(commandApdu);
        if (apdu.getCLA() == 0x00 && apdu.getINS() == 0xa4 && apdu.getP1() == 0x04 && apdu.getP2() == 0x00) {
            return SW_SUCCESS;
        }

        if ((apdu.getCLA() & 0x80) != 0x80) {
            return SW_CLA_NOT_SUPPORTED;
        }

        switch (apdu.getINS()) {
            case INS_GET_PUBLIC_KEY:
                return processGetPublicKey();
            case INS_AUTHENTICATE:
                return processAuthenticate(apdu.getData());
            case INS_GET_CARD_INFO:
                return processGetCardInfo();
            default:
                return SW_INS_NOT_SUPPORTED;
        }
    }

    private byte[] processGetCardInfo() {
        return new byte[]{0x00, 0x01, (byte) 0x90, 0x00};
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePrivate(prvkey);
    }

    public static PublicKey loadPublicKey(byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(pubKey);
    }

    private ECPublicKey getPublicKeyFromPrivate(ECPrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");

        BigInteger d = privateKey.getD();
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
                privateKey.getParameters();
        ECPoint Q = privateKey.getParameters().getG().multiply(d);

        org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new
                org.bouncycastle.jce.spec.ECPublicKeySpec(Q, ecSpec);
        return (ECPublicKey) keyFactory.generatePublic(pubSpec);
    }

    private byte[] processGetPublicKey() {
        try {

            ECPrivateKey privKey = (ECPrivateKey) loadPrivateKey(decryptRSA(Hex.decode(sharedPreferences.getString(KEY_ALIAS, ""))));
            ECPublicKey pubKey = getPublicKeyFromPrivate(privKey);

            byte[] resp = new byte[67];
            System.arraycopy(pubKey.getQ().getEncoded(false), 0, resp, 0, 65);
            resp[65] = (byte) 0x90;
            resp[66] = 0x00;

            return resp;
        } catch (Exception e) {
            e.printStackTrace();
            return SW_UNKNOWN;
        }

    }

    private byte[] processAuthenticate(byte[] buffer) {
        if (buffer.length < 0x51) {
            return SW_WRONG_LENGTH;
        }

        byte[] pubKey = new byte[65];
        System.arraycopy(buffer, 0, pubKey, 0, 65);
        byte[] challenge = new byte[16];
        byte[] salt = new byte[4];
        random.nextBytes(salt);
        System.arraycopy(salt, 0, challenge, 0, 4);
        System.arraycopy(buffer, 69, challenge, 4, 12);
        try {
            ECPrivateKey privKey = (ECPrivateKey) loadPrivateKey(decryptRSA(Hex.decode(sharedPreferences.getString(KEY_ALIAS, ""))));
            byte[] resp = new byte[18];
            System.arraycopy(doAuthenticate(privKey, pubKey, challenge), 0, resp, 0, 16);
            resp[16] = (byte) 0x90;
            resp[17] = 0x00;
            return resp;
        } catch (Exception e) {
            e.printStackTrace();
            return SW_UNKNOWN;
        }
    }


    private byte[] doECDH(PrivateKey privKey, byte[] pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(privKey);
        ka.doPhase(loadPublicKey(pubKey), true);
        return ka.generateSecret();
    }

    private byte[] getEncryptKey(PrivateKey privKey, byte[] pubKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(doECDH(privKey, pubKey));
            byte[] key = new byte[16];
            System.arraycopy(digest.digest(), 0, key, 0, 16);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] doAuthenticate(PrivateKey privKey, byte[] pubKey, byte[] challenge) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKeySpec keySpec = new SecretKeySpec(getEncryptKey(privKey, pubKey), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(challenge);

    }


    private byte[] decryptRSA(byte[] ciphertext) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(ciphertext);
    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            return;
        }
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @Override
    public void onDeactivated(int reason) {

    }
}