package li.power.app.wearos.teslanak;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.TextView;
import androidx.core.splashscreen.SplashScreen;
import li.power.app.wearos.teslanak.databinding.ActivityMainBinding;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class MainActivity extends Activity {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "tesla_nak";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";


    private KeyStore keyStore;
    private SharedPreferences sharedPreferences;


    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        SplashScreen.installSplashScreen(this);

        sharedPreferences = getSharedPreferences(KEY_ALIAS, Context.MODE_PRIVATE);

        li.power.app.wearos.teslanak.databinding.ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        TextView mTextView = binding.text;

        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateEccPrivateKey();
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            mTextView.setText("Failed to initialize keystore.");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException e) {
            mTextView.setText("Failed to generate keypair.");
            e.printStackTrace();
        }
        mTextView.setText("Tesla key card is ready. Keep app active and present as required.");
    }


    private void generateEccPrivateKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, KeyStoreException, BadPaddingException, InvalidKeyException {
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keyParams);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        generateRsaKey();
        sharedPreferences.edit().putString(KEY_ALIAS, Hex.encodeHexString(encryptRSA(((ECPrivateKeyParameters)keyPair.getPrivate()).getD().toByteArray()))).apply();
    }

    private byte[] encryptRSA(byte[] plainText) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();

        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(plainText);
    }


    private void generateRsaKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);
        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();
    }


}