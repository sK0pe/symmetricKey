package com.company;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.prng.FixedSecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Created by Pradyumn on 2/5/2017.
 */
public class AES_CBC {
    PaddedBufferedBlockCipher encryptCipher = null;
    PaddedBufferedBlockCipher decryptCipher = null;

    // buffers to transport bytes from one stream to another
    byte[] buf = new byte[16];
    byte[] obuf = new byte[512];
    // key
    byte[] key = null;
    // iv
    byte[] IV = null;

    // the default block size
    public static final int BLOCKSIZE = 16;

    // constructor
    public AES_CBC(){
        key = "secret_1secret_2secret_3".getBytes();
        SecureRandom random = new SecureRandom();
        // default iv, all bytes to 0
        IV = new byte[BLOCKSIZE];
        random.nextBytes(IV);
    }

    public AES_CBC(byte[] keyBytes){
        // get key
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
        // default IV vector with all bytes to 0
        IV = new byte[BLOCKSIZE];
    }

    public AES_CBC(byte[] keyBytes, byte[] iv){
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
        IV = new byte[BLOCKSIZE];
        System.arraycopy(iv, 0, IV, 0, iv.length);
    }

    public void InitCiphers(){
        // create ciphers
        // AES block cipher in CBC mode with padding
        encryptCipher = new PaddedBufferedBlockCipher( new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        // create the IV parameter
        ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(key), IV);

        encryptCipher.init(true, parameterIV);
        decryptCipher.init(false, parameterIV);
    }

    public void resetCiphers(){
        if(encryptCipher != null){
            encryptCipher.reset();
        }
        if(decryptCipher != null){
            decryptCipher.reset();
        }
    }


    public void symmetricEncrypt(InputStream in, OutputStream out)  throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException{
        // bytes written to out will be encrypted
        // read in the cleartext bytes from inputstream and write them encrypted

        // write IV at the start of the outputstream
        out.write(IV, 0, IV.length);

        int noBytesRead = 0;    // num bytes read from input
        int noBytesProcessed = 0;   // num bytes processed

        while((noBytesRead = in.read(buf)) >= 0){
            noBytesProcessed = encryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
            out.write(obuf, 0, noBytesProcessed);
        }
        // make sure final set of bytes read
        noBytesProcessed = encryptCipher.doFinal(obuf, 0);
        out.write(obuf, 0, noBytesProcessed);
        out.flush();

        in.close();
        out.close();
    }


    public void symmetricDecrypt(InputStream in, OutputStream out) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException {
        // Bytes encrypted from inputstream will be read indecrypted to cleartext and output

        // get IV from file
        in.read(IV, 0, IV.length);
        this.InitCiphers();

        int noBytesRead = 0;        // number of bytes read from input
        int noBytesProcessed = 0;     // number of bytes processed

        while((noBytesRead = in.read(buf)) >= 0){
            System.out.println(noBytesRead + " bytes read");
            noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
            System.out.println(noBytesProcessed + " bytes decrypted");
            out.write(obuf, 0, noBytesProcessed);
        }
        noBytesProcessed = decryptCipher.doFinal(obuf, 0);
        out.write(obuf, 0, noBytesProcessed);

        out.flush();
        in.close();
        out.close();
    }


}
