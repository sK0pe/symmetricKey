package com.company;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSalt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by Pradyumn on 2/5/2017.
 */
public class BouncyCastleProvider_AES_CBC{

    // The default block size
    public static int blockSize = 16;

    Cipher encryptCipher = null;
    Cipher decryptCipher = null;

    // Buffer used to transport the bytes from one stream to another
    byte[] buf = new byte[blockSize];       //input buffer
    byte[] obuf = new byte[512];            //output buffer

    // The key
    byte[] key = null;
    // The initialization vector needed by the CBC mode
    byte[] IV = null;

    public BouncyCastleProvider_AES_CBC(){
        //for a 192 key you must install the unrestricted policy files
        //  from the JCE/JDK downloads page
        key = "SECRET_1SECRET_2".getBytes();
        //default IV value initialized with 0
        IV = new byte[blockSize];
    }

    public BouncyCastleProvider_AES_CBC(String pass, byte[] iv){
        //get the key and the IV
        key = pass.getBytes();
        IV = new byte[blockSize];
        System.arraycopy(iv, 0 , IV, 0, iv.length);
    }
    public BouncyCastleProvider_AES_CBC(byte[] pass, byte[]iv){
        //get the key and the IV
        key = new byte[pass.length];
        System.arraycopy(pass, 0 , key, 0, pass.length);
        IV = new byte[blockSize];
        System.arraycopy(iv, 0 , IV, 0, iv.length);
    }

    public void InitCiphers()
            throws NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException {
        //1. create the cipher using Bouncy Castle Provider
        encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        //2. create the key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        SecretKey keyValue = keyGen.generateKey();
        //3. create the IV
        AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);
        //4. init the cipher
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);

        //1 create the cipher
        decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        //2. the key is already created
        //3. the IV is already created
        //4. init the cipher
        decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
    }

    public void ResetCiphers()
    {
        encryptCipher=null;
        decryptCipher=null;
    }

    public void CBCEncrypt(InputStream fis, OutputStream fos)
            throws IOException,
            ShortBufferException,
            IllegalBlockSizeException,
            BadPaddingException {
        //optionally put the IV at the beggining of the cipher file
        fos.write(IV, 0, IV.length);

        byte[] buffer = new byte[blockSize];
        int noBytes = 0;
        byte[] cipherBlock =
                new byte[encryptCipher.getOutputSize(buffer.length)];
        int cipherBytes;
        while((noBytes = fis.read(buffer))!=-1)
        {
            cipherBytes =
                    encryptCipher.update(buffer, 0, noBytes, cipherBlock);
            fos.write(cipherBlock, 0, cipherBytes);
        }
        //always call doFinal
        cipherBytes = encryptCipher.doFinal(cipherBlock,0);
        fos.write(cipherBlock,0,cipherBytes);

        //close the files
        fos.close();
        fis.close();
    }

    public void CBCDecrypt(InputStream fis, OutputStream fos)
            throws IOException,
            ShortBufferException,
            IllegalBlockSizeException,
            BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // get the IV from the file
        // DO NOT FORGET TO reinit the cipher with the IV
        fis.read(IV,0,IV.length);
        this.InitCiphers();

        byte[] buffer = new byte[blockSize];
        int noBytes = 0;
        byte[] cipherBlock =
                new byte[decryptCipher.getOutputSize(buffer.length)];
        int cipherBytes;
        while((noBytes = fis.read(buffer))!=-1){
            cipherBytes =
                    decryptCipher.update(buffer, 0, noBytes, cipherBlock);
            fos.write(cipherBlock, 0, cipherBytes);
        }
        //allways call doFinal
        cipherBytes = decryptCipher.doFinal(cipherBlock,0);
        fos.write(cipherBlock,0,cipherBytes);

        //close the files
        fos.close();
        fis.close();
    }

    public String dec(String  password, String salt, String encString) throws InvalidCipherTextException, UnsupportedEncodingException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] ivData = toByte(encString.substring(0, 32));
        byte[] encData = toByte(encString.substring(32));

        // get raw key from password and salt
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), toByte(salt), 50, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
        SecretKeySpec secretKey = new SecretKeySpec(keyFactory.generateSecret(pbeKeySpec).getEncoded(), "AES");
        byte[] key = secretKey.getEncoded();

        // setup cipher parameters with key and IV
        KeyParameter keyParam = new KeyParameter(key);
        CipherParameters params = new ParametersWithIV(keyParam, ivData);

        // setup AES cipher in CBC mode with PKCS7 padding
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new AESEngine()), padding);
        cipher.reset();
        cipher.init(false, params);

        // create a temporary buffer to decode into (it'll include padding)
        byte[] buf = new byte[cipher.getOutputSize(encData.length)];
        int len = cipher.processBytes(encData, 0, encData.length, buf, 0);
        len += cipher.doFinal(buf, len);

        // remove padding
        byte[] out = new byte[len];
        System.arraycopy(buf, 0, out, 0, len);

        // return string representation of decoded bytes
        return new String(out, "UTF-8");
    }

    private byte[] toByte(String salt) {
        return salt.getBytes(StandardCharsets.UTF_8);
    }
}
