package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.utils;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.Main;

public class Encryption {
    private static final String TAG = "BT-Enc";
    private static Encryption mInstance;
    private static Context mContext;

    //    private final String ALGORITHM = "RSA"
    private final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private PublicKey publicKeyDaemon;

    public boolean loadDaemonsKeySuccessful = false;

    private SharedPreferences sharedpreferences;

    public static Encryption getInstance(Context _context) {
        if (mInstance == null) {
            mContext = _context;
            mInstance = new Encryption();
        }
        return mInstance;
    }

    private Encryption() {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        sharedpreferences = mContext.getSharedPreferences("btProximity", Context.MODE_PRIVATE);

        if (getPrivateKey() == null && getPublicKey() == null) {
            Log.d(TAG, "fetching of keys failed.. going to generate");
            RSAKeyGen();
        }
    }

    public String encryptAES128(String plaintext, String key) {
        Log.d(TAG, "Going to encrypt " + plaintext);
        try {
            SharedPreferences sharedpreferences = mContext.getSharedPreferences("btProximity", Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = sharedpreferences.edit();

            byte[] salt = saltGeneration();
            editor.putString("salt", Base64.toBase64String(salt));
            editor.apply();

            /*
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "SC");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 65536, 256);
            SecretKey tmp = keyFactory.generateSecret(spec);
            */

            // work around for the support of "PBKDF2WithHmacSHA256"
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
            generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(key.toCharArray()), salt, 65536);
            KeyParameter keyp = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKey secret = new SecretKeySpec(keyp.getKey(), "AES"); // used to be tmp.getEncoded()

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secret);

            AlgorithmParameters parms = cipher.getParameters();
            byte[] iv = parms.getParameterSpec(IvParameterSpec.class).getIV();

            editor.putString("iv", Base64.toBase64String(iv));
            editor.apply();

            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            Log.d(TAG, "encrypted sucessfully");
            return Base64.toBase64String(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidParameterSpecException e) {
            Log.d(TAG, "encrypted UNsucessfully!");
            Log.e(TAG, e.getMessage());
            return null;
        }
    }

    public String decryptAES128(String encrypted, String key) {
        Log.d(TAG, "Going to decrypt " + encrypted);
        String ret = null;
        try {
            SharedPreferences sharedpreferences = mContext.getSharedPreferences("btProximity", Context.MODE_PRIVATE);
            String strIV = sharedpreferences.getString("iv", null);
            String strSalt = sharedpreferences.getString("salt", null);

            if (strIV != null && strSalt != null) {

                byte[] iv = Base64.decode(strIV);
                byte[] salt = Base64.decode(strSalt);

                // work around for the support of "PBKDF2WithHmacSHA256"
                PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
                generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(key.toCharArray()), salt, 65536);
                KeyParameter keyp = (KeyParameter) generator.generateDerivedParameters(256);

                SecretKey secret = new SecretKeySpec(keyp.getKey(), "AES"); // used to be tmp.getEncoded()

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

                byte[] plain = cipher.doFinal(Base64.decode(encrypted));
                ret = new String(plain);
                Log.d(TAG, "decrypted sucessfully -> " + ret);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            Log.d(TAG, "decrypted UNsucessfully!");
            Log.e(TAG, e.getMessage());
        }
        return ret;
    }

    private byte[] saltGeneration() {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(8);
    }

    // RSA
    private boolean RSAKeyGen() {
        Log.d(TAG, "...generate RSA keypair");
        try {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("BTPC", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(2048)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build();

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            gen.initialize(spec, random);
            gen.generateKeyPair();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.e(TAG, e.getMessage());
            return false;
        }
        Log.d(TAG, "...Successfully");
        return true;
    }

    public byte[] encryptRSA(String _plain, PublicKey _pubKey) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, _pubKey);
            return cipher.doFinal(_plain.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            Log.e(TAG, e.getMessage());
            return null;
        }
    }

    public String decryptRSA(byte[] _encrypted, PrivateKey _privKey) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, _privKey);
            return new String(cipher.doFinal(_encrypted));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            Log.e(TAG, e.getMessage());
            return null;
        }
    }

    public String signRSA(String _data, PrivateKey _privKey) {
        final Signature signature;
        try {
            signature = Signature.getInstance("RSA");
            signature.initSign(_privKey);
            signature.update(_data.getBytes());
            byte[] signedDataBytes = signature.sign();
            return new String(Base64.encode(signedDataBytes));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.e(TAG, e.getMessage());
            return null;
        }
    }

    public boolean verifyRSA(byte[] _data, byte[] _signData, PublicKey _pubKey) {
        final Signature signature;
        try {
            signature = Signature.getInstance("SHA256withRSA", PROVIDER);
            signature.initVerify(_pubKey);
            signature.update(_data);
            return signature.verify(_signData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            Log.e(TAG, e.getMessage());
            return false;
        }
    }

    public PrivateKey getPrivateKey() {
        PrivateKey privKey = null;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("BTPC", null);
            if (privKeyEntry != null) {
                privKey = privKeyEntry.getPrivateKey();
            }
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Log.e(TAG, e.getMessage());
        }
        return privKey;
    }

    public PublicKey getPublicKey() {
        PublicKey pubKey = null;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("BTPC", null);
            if (privKeyEntry != null) {
                pubKey = privKeyEntry.getCertificate().getPublicKey();
            }
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Log.e(TAG, e.getMessage());
            return null;
        }
        return pubKey;
    }

    // Daemons Public Key
    public boolean loadPublicKeyDaemon(String fileLocation) {         // parameter file loation
        byte[] encodedPublicKey;
        byte[] decodedPublicKey;

        try {
            Log.d(TAG, "loadPublicKeyDaemon() location: " + fileLocation);

            File pbkeyFile = new File(fileLocation);
            FileInputStream fis = new FileInputStream(pbkeyFile);
            DataInputStream dis = new DataInputStream(fis);

            encodedPublicKey = new byte[(int) pbkeyFile.length()];
            dis.readFully(encodedPublicKey);
            dis.close();

            decodedPublicKey = Base64.decode(encodedPublicKey);
        } catch (IOException e) {
            Log.e(TAG, "IOE loadPublicKeyDaemon", e);
            return false;
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodedPublicKey);
            publicKeyDaemon = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            Log.e(TAG, "[ERROR] Daemon PB-Key", e);
            return false;
        }
        Log.d(TAG, "[SUCCESS] Daemon PB-Key");
        return true;
    }

    public boolean fetchPublicKeyDaemon() {
        // try to load selected public key

        String pathToPBDaemon = sharedpreferences.getString("pathPBDaemon", null);
        Log.d(TAG, "fetchPublicKeyDaemon: path to pb-key: " + pathToPBDaemon);

        if (pathToPBDaemon != null) {
            return loadPublicKeyDaemon(pathToPBDaemon);
        } else {
            // else call let user pick from storage
            loadPublicKeyDaemonFromFile();
            return loadDaemonsKeySuccessful;
        }
    }

    public void loadPublicKeyDaemonFromFile() {
        // load daemons' public key from android storage to authenticate communication
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/x-x509-ca-cert"); // set MIME correctly
        intent = Intent.createChooser(intent, "choose file");

        ((Main) mContext).startActivityForResult(intent, Main.READ_REQUEST_CODE);
    }

    public PublicKey getPublicKeyDaemon() {
        return publicKeyDaemon;
    }

//    public PublicKey convertPublicKey(String publicKey) {
//        PublicKey pubKey = null;
//        try {
//            X509EncodedKeySpec x509 = new X509EncodedKeySpec(Base64.decode(publicKey));
//            KeyFactory kf = KeyFactory.getInstance("RSA/ECB/PKCS1PADDING", PROVIDER);
//            pubKey = kf.generatePublic(x509);
//        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
//            Log.e(TAG, e.getMessage());
//        }
//        return pubKey;
//    }

    // OTP, Key, HMAC stuff
    public boolean updateOTP(String otp) {
        SharedPreferences.Editor editor = sharedpreferences.edit();

        editor.putString("otp", otp);
        if (editor.commit()) {
            Log.d(TAG, "saved (new) OTP: " + otp);
            return true;
        } else {
            return false;
        }
    }

    public String getOTP() {
        Log.d(TAG, "...get OTP");
        return sharedpreferences.getString("otp", null);
    }

    public void updateHMACKey(String hmac) {
        String encryptedHMAC = encryptAES128(hmac, "TODO");  // TODO set AES key

        SharedPreferences.Editor editor = sharedpreferences.edit();
        editor.putString("hmac", encryptedHMAC);
        if (editor.commit()) {
            Log.d(TAG, "saved (new) key: " + encryptedHMAC);
        }
    }

    public String getHMACKey() {
        Log.d(TAG, "...get Key");
        String encryptedKey = sharedpreferences.getString("hmac", null);
        return decryptAES128(encryptedKey, "TODO"); // TODO set AES key
    }

    public String createHMAC(String msg, String keyString) {
        String digest = null;
        try {
            SecretKeySpec key = new SecretKeySpec((keyString).getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            byte[] bytes = mac.doFinal(msg.getBytes(StandardCharsets.US_ASCII));

            StringBuilder hash = new StringBuilder();
            for (byte aByte : bytes) {
                String hex = Integer.toHexString(0xFF & aByte);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }

            digest = hash.toString();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return digest;
    }
}
