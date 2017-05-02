package com.company;

import org.bouncycastle.crypto.DataLengthException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    public static void main(String[] args) throws FileNotFoundException {
        try{
            FileInputStream fis = new FileInputStream(new File("clear.txt"));
            FileOutputStream fos = new FileOutputStream(new  File("encrypt.txt"));
            AES_CBC bc = new AES_CBC();
            bc.InitCiphers();
            // encryption
            bc.symmetricEncrypt(fis, fos);

            fis = new FileInputStream(new File("encrypt.txt"));
            fos = new FileOutputStream(new File("clear_test.txt"));

            // decryption
            bc.symmetricDecrypt(fis, fos);
        }
        catch (ShortBufferException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (DataLengthException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
