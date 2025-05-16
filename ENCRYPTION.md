# Secret Encryption Dokumentation

## Überblick
Die Implementierung bietet eine sichere Verschlüsselung von Benutzergeheimnissen mit AES-256 mit CBC-Modus, wobei sowohl IV (Initialisierungsvektor) als auch Salt für eine erhöhte Sicherheit integriert sind.

## Schlüsselsicherheitsmerkmale

1. **AES-256 Verschlüsselung**
   - Verwendet den CBC-Modus mit PKCS5-Padding
   - 256-Bit-Schlüssellänge für maximale Sicherheit

2. **Sicherheitsmassnahmen**
   - Zufällige IV (16 Bytes) für jede Verschlüsselung
   - Eindeutiges Salt (32 Bytes) für die Schlüsselableitung
   - PBKDF2 mit 65.536 Iterationen zur Schlüsselverstärkung

3. **Datenstruktur**
```
Base64(Salt[32] + IV[16] + EncryptedData[n])
```

## Verwendung
```java
// Verschlüsselung
EncryptUtil encryptor = new EncryptUtil(userPassword);
String encrypted = encryptor.encrypt(secretContent);

// Entschlüsselung
String decrypted = encryptor.decrypt(encrypted);
````

