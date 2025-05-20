# In SecretController.java: 

Hier wird das Secret Encrypted:

```java
@PostMapping
...
String encryptedContent = new EncryptUtil(newSecret.getEncryptPassword()).encrypt(newSecret.getContent());

```

Hier wird das Secret mit dem User Email verknüpft und gespeichert: 

```java 
@PostMapping("/byemail")
... 
secret.setContent(new EncryptUtil(credentials.getEncryptPassword()).decrypt(secret.getContent()));

```

# In EncryptUtil.java:

Hier wird der Secret content encrypted mit salt und IV. 

```java
public String encrypt(String data) {

   ...
   byte[] salt = new byte[SALT_SIZE];
   new SecureRandom().nextBytes(salt);

   ...
   byte[] iv = new byte[IV_SIZE];
   new SecureRandom().nextBytes(iv);
   IvParameterSpec ivSpec = new IvParameterSpec(iv);
}
```

Die "decrypt()"-Funktion funktioniert auf der selben Art, aber verkehrt. 

Beide Funktionen benutzen einen Key der in der "deriveKey()" definiert wird. Diese Funktion nutz ein Password, dass das Passwort des eingeloggten users ist. 

```java
private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
   ...
   byte[] key = factory.generateSecret(spec).getEncoded();
}

```

# In NewSecret.java:

Hier musste der "content"-Wert auf String, statt JSON gewechselt werden. Änderungen auf der Datenbank waren natürlich auch nötig. 

```java
   @NotNull (message="secret is required.")
   private String content;
```