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
               
        return errors;
    }
} 