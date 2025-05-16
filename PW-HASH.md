# In PasswordEncryptionService:

Salt wird zufällig generiert (SecureRandom), bei jeder Passwortspeicherung neu.

Pepper ist ein fester geheimer String (PEPPER), hartkodiert im Code.

# Beim Hashen "hash()":

SHA-256 wird verwendet.

Reihenfolge: salt, dann pepper, dann das Passwort.

Ergebnis wird Base64-codiert.

Rückgabeformat: salt:hash.

# Beim Login "doPasswordMatch()":

Salt wird aus gespeichertem String extrahiert. 

Passwort wird erneut mit diesem Salt und dem Pepper gehasht.

Verglichen mit gespeicherten Hash.