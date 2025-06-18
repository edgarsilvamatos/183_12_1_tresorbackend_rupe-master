package ch.bbw.pr.tresorbackend.util;

import org.springframework.stereotype.Component;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

@Component
public class PasswordValidator {
    private static final String PASSWORD_PATTERN = 
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&+])[A-Za-z\\d@$!%*?&]{8,}$";
    
    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);
    
    public List<String> validatePassword(String password) {
        List<String> errors = new ArrayList<>();
        
        if (password == null || password.length() < 8) {
            errors.add("Password must be at least 8 characters long");
        }
        
        if (password != null && password.length() > 128) {
            errors.add("Password must not exceed 128 characters");
        }
        
        // if (!pattern.matcher(password).matches()) {
        //     errors.add("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
        // }
        
        // Check for common patterns
        // if (containsSequentialChars(password)) {
        //     errors.add("Password must not contain sequential characters");
        // }
        
        // if (containsRepeatedChars(password)) {
        //     errors.add("Password must not contain repeated characters");
        // }
        
        return errors;
    }
    
    private boolean containsSequentialChars(String password) {
        if (password == null) return false;
        
        // Check for sequential numbers
        for (int i = 0; i < password.length() - 2; i++) {
            if (Character.isDigit(password.charAt(i)) &&
                Character.isDigit(password.charAt(i + 1)) &&
                Character.isDigit(password.charAt(i + 2))) {
                int num1 = Character.getNumericValue(password.charAt(i));
                int num2 = Character.getNumericValue(password.charAt(i + 1));
                int num3 = Character.getNumericValue(password.charAt(i + 2));
                if (num2 == num1 + 1 && num3 == num2 + 1) {
                    return true;
                }
            }
        }
        
        // Check for sequential letters
        for (int i = 0; i < password.length() - 2; i++) {
            if (Character.isLetter(password.charAt(i)) &&
                Character.isLetter(password.charAt(i + 1)) &&
                Character.isLetter(password.charAt(i + 2))) {
                char c1 = Character.toLowerCase(password.charAt(i));
                char c2 = Character.toLowerCase(password.charAt(i + 1));
                char c3 = Character.toLowerCase(password.charAt(i + 2));
                if (c2 == c1 + 1 && c3 == c2 + 1) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private boolean containsRepeatedChars(String password) {
        if (password == null) return false;
        
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) &&
                password.charAt(i) == password.charAt(i + 2)) {
                return true;
            }
        }
        
        return false;
    }
} 