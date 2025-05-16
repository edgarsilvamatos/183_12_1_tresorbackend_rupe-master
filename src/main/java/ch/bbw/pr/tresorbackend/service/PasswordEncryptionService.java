package ch.bbw.pr.tresorbackend.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Service;

/**
 * PasswordEncryptionService
 * @author Peter Rutschmann
 */
@Service
public class PasswordEncryptionService {
   private static final SecureRandom random = new SecureRandom();
   private static final String PEPPER = "YourSecretPepper"; 

   public PasswordEncryptionService() {
      System.out.println("PasswordEncryptionService is initialized");
   }

   // Hash the password with salt and pepper
   public String hashPassword(String password) {
      byte[] salt = new byte[16];
      random.nextBytes(salt);
      String hash = hash(password, salt);
      System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
      System.out.println("Hash: " + hash);
      return Base64.getEncoder().encodeToString(salt) + ":" + hash;
  }

   // Verify if the password matches the hash stored in the database
   public boolean doPasswordMatch(String password, String stored) {
      String[] parts = stored.split(":");
      byte[] salt = Base64.getDecoder().decode(parts[0]);
      String hash = hash(password, salt);
      return parts[1].equals(hash);
   }

   // Perform the hashing with SHA-256, salt, and pepper
   private String hash(String password, byte[] salt) {
      try {
          MessageDigest md = MessageDigest.getInstance("SHA-256");
          md.update(salt);
          md.update(PEPPER.getBytes(StandardCharsets.UTF_8));
          byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
          String hashedString = Base64.getEncoder().encodeToString(hashed);
          System.out.println("Hashed password: " + hashedString);
          return hashedString;
      } catch (Exception e) {
          e.printStackTrace();
          throw new RuntimeException("Error hashing password", e);
      }
  }
  
}
