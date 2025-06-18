package ch.bbw.pr.tresorbackend.controller;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;
import ch.bbw.pr.tresorbackend.model.EmailAdress;
import ch.bbw.pr.tresorbackend.model.RegisterUser;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptionService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.util.RecaptchaService;
import ch.bbw.pr.tresorbackend.util.PasswordValidator;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

/**
 * UserController
 * @author Peter Rutschmann
 */
@RestController
@AllArgsConstructor
@RequestMapping("api/users")
public class UserController {

   private UserService userService;
   private PasswordEncryptionService passwordService;
   private final ConfigProperties configProperties;
   private PasswordValidator passwordValidator;
   private RecaptchaService recaptchaService;
   private static final Logger logger = LoggerFactory.getLogger(UserController.class);

   @Autowired
   public UserController(ConfigProperties configProperties, UserService userService,
                         PasswordEncryptionService passwordService,
                         PasswordValidator passwordValidator,
                         RecaptchaService recaptchaService) {
      this.configProperties = configProperties;
      System.out.println("UserController.UserController: cross origin: " + configProperties.getOrigin());
      // Logging in the constructor
      logger.info("UserController initialized: " + configProperties.getOrigin());
      logger.debug("UserController.UserController: Cross Origin Config: {}", configProperties.getOrigin());
      this.userService = userService;
      this.passwordService = passwordService;
      this.passwordValidator = passwordValidator;
      this.recaptchaService = recaptchaService;
   }

   // build create User REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createUser(@Valid @RequestBody RegisterUser registerUser, BindingResult bindingResult) {
      // ReCAPTCHA verification
      if (!recaptchaService.verifyRecaptcha(registerUser.getRecaptchaToken())) {
         logger.warn("ReCAPTCHA verification failed for registration attempt");
         JsonObject obj = new JsonObject();
         JsonArray arr = new JsonArray();
         arr.add("ReCAPTCHA verification failed");
         obj.add("message", arr);
         return ResponseEntity.badRequest().body(new Gson().toJson(obj));
      }
      logger.info("ReCAPTCHA verification passed");

      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);
         return ResponseEntity.badRequest().body(json);
      }

      List<String> passwordErrors = passwordValidator.validatePassword(registerUser.getPassword());
      if (!passwordErrors.isEmpty()) {
         logger.warn("Password validation failed: {}", passwordErrors);
         JsonArray arr = new JsonArray();
         passwordErrors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         return ResponseEntity.badRequest().body(new Gson().toJson(obj));
      }
      logger.info("Password validation passed");

      // === Save user ===
      User user = new User(
            null,
            registerUser.getFirstName(),
            registerUser.getLastName(),
            registerUser.getEmail(),
            passwordService.hashPassword(registerUser.getPassword())
      );
      userService.createUser(user);
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", "User Saved");
      return ResponseEntity.accepted().body(new Gson().toJson(obj));
   }

   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("/reset-password")
   public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> payload) {
      String email = payload.get("email");
      String newPassword = payload.get("newPassword");

      if (email == null || newPassword == null) {
         return ResponseEntity.badRequest().body("{\"message\":\"Email and new password required\"}");
      }

      User user = userService.findByEmail(email);
      if (user == null) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\":\"User not found\"}");
      }

      user.setPassword(passwordService.hashPassword(newPassword));
      userService.updateUser(user);

      return ResponseEntity.ok("{\"message\":\"Password reset successful\"}");
   }

   // User login
   @PostMapping("/login")
   public ResponseEntity<String> doLoginUser(@RequestBody User loginUser) {
      User user = userService.findByEmail(loginUser.getEmail());
      if (user != null && passwordService.doPasswordMatch(loginUser.getPassword(), user.getPassword())) {
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "Login successful");
         obj.addProperty("userId", user.getId());
         return ResponseEntity.ok(new Gson().toJson(obj));
      }
      JsonObject obj = new JsonObject();
      obj.addProperty("message", "Login failed");
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new Gson().toJson(obj));
   }

   // build get user by id REST API
   // http://localhost:8080/api/users/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping("{id}")
   public ResponseEntity<User> getUserById(@PathVariable("id") Long userId) {
      User user = userService.getUserById(userId);
      return new ResponseEntity<>(user, HttpStatus.OK);
   }

   // Build Get All Users REST API
   // http://localhost:8080/api/users
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<User>> getAllUsers() {
      List<User> users = userService.getAllUsers();
      return new ResponseEntity<>(users, HttpStatus.OK);
   }

   // Build Update User REST API
   // http://localhost:8080/api/users/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<User> updateUser(@PathVariable("id") Long userId,
                                          @RequestBody User user) {
      user.setId(userId);
      User updatedUser = userService.updateUser(user);
      return new ResponseEntity<>(updatedUser, HttpStatus.OK);
   }

   // Build Delete User REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteUser(@PathVariable("id") Long userId) {
      userService.deleteUser(userId);
      return new ResponseEntity<>("User successfully deleted!", HttpStatus.OK);
   }


   // get user id by email
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<String> getUserIdByEmail(@RequestBody EmailAdress email, BindingResult bindingResult) {
      System.out.println("UserController.getUserIdByEmail: " + email);
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("UserController.createUser " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("UserController.createUser, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      System.out.println("UserController.getUserIdByEmail: input validation passed");

      User user = userService.findByEmail(email.getEmail());
      if (user == null) {
         System.out.println("UserController.getUserIdByEmail, no user found with email: " + email);
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "No user found with this email");
         String json = new Gson().toJson(obj);

         System.out.println("UserController.getUserIdByEmail, fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.getUserIdByEmail, user find by email");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", user.getId());
      String json = new Gson().toJson(obj);
      System.out.println("UserController.getUserIdByEmail " + json);
      return ResponseEntity.accepted().body(json);
   }

}
