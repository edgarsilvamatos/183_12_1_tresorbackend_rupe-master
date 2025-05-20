package ch.bbw.pr.tresorbackend.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptUtil {
   private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
   private static final int KEY_SIZE = 256;
   private static final int IV_SIZE = 16;
   private static final int SALT_SIZE = 16;
   private static final int ITERATIONS = 65536;

   private final String password;

   public EncryptUtil(String secretKey) {
      this.password = secretKey;
   }

   public String encrypt(String data) {
      try {
         byte[] salt = new byte[SALT_SIZE];
         new SecureRandom().nextBytes(salt);

         SecretKeySpec key = deriveKey(password, salt);
         Cipher cipher = Cipher.getInstance(ALGORITHM);

         byte[] iv = new byte[IV_SIZE];
         new SecureRandom().nextBytes(iv);
         IvParameterSpec ivSpec = new IvParameterSpec(iv);

         cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         byte[] encrypted = cipher.doFinal(data.getBytes());

         byte[] combined = new byte[salt.length + iv.length + encrypted.length];
         System.arraycopy(salt, 0, combined, 0, salt.length);
         System.arraycopy(iv, 0, combined, salt.length, iv.length);
         System.arraycopy(encrypted, 0, combined, salt.length + iv.length, encrypted.length);

         return Base64.getEncoder().encodeToString(combined);
      } catch (Exception e) {
         throw new RuntimeException("Encryption failed", e);
      }
   }

   public String decrypt(String encryptedData) {
      try {
         byte[] combined = Base64.getDecoder().decode(encryptedData);

         byte[] salt = new byte[SALT_SIZE];
         byte[] iv = new byte[IV_SIZE];
         byte[] encrypted = new byte[combined.length - SALT_SIZE - IV_SIZE];

         System.arraycopy(combined, 0, salt, 0, SALT_SIZE);
         System.arraycopy(combined, SALT_SIZE, iv, 0, IV_SIZE);
         System.arraycopy(combined, SALT_SIZE + IV_SIZE, encrypted, 0, encrypted.length);

         SecretKeySpec key = deriveKey(password, salt);
         Cipher cipher = Cipher.getInstance(ALGORITHM);
         cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

         byte[] decrypted = cipher.doFinal(encrypted);
         return new String(decrypted);
      } catch (Exception e) {
         throw new RuntimeException("Decryption failed", e);
      }
   }

   private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
      byte[] key = factory.generateSecret(spec).getEncoded();
      return new SecretKeySpec(key, "AES");
   }
}
