package ch.bbw.pr.tresorbackend.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import java.util.List;
import java.util.Map;
import jakarta.annotation.PostConstruct;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

@Service
public class RecaptchaService {
    private static final Logger logger = LoggerFactory.getLogger(RecaptchaService.class);
    
    // Hardcoded ReCAPTCHA keys
    private static final String SECRET_KEY = "6LenF1QrAAAAAIZ3Kc-JOGyV3YU4bZIOrlGdf9PX";
    private static final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    // Define timeouts in milliseconds
    private static final int CONNECT_TIMEOUT_MS = 5000; // 5 seconds
    private static final int READ_TIMEOUT_MS = 10000;  // 10 seconds
    
    @PostConstruct
    public void init() {
        logger.info("Initializing ReCAPTCHA service with secret key: {}****{}", 
            SECRET_KEY.substring(0, 2), 
            SECRET_KEY.substring(SECRET_KEY.length() - 2));
    }
    
    public boolean verifyRecaptcha(String recaptchaResponse) {
        if (recaptchaResponse == null || recaptchaResponse.isEmpty()) {
            logger.warn("ReCAPTCHA response is null or empty");
            return false;
        }

        logger.info("Received recaptchaToken: {}", recaptchaResponse);

        logger.debug("Verifying ReCAPTCHA response: {}...", 
            recaptchaResponse.substring(0, Math.min(10, recaptchaResponse.length())));
        
        try {
            SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
            requestFactory.setConnectTimeout(CONNECT_TIMEOUT_MS);
            requestFactory.setReadTimeout(READ_TIMEOUT_MS);

            RestTemplate restTemplate = new RestTemplate(requestFactory);
            
            // Set up headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            // Set up request body
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("secret", SECRET_KEY);
            map.add("response", recaptchaResponse);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            
            // Make the request
            Map<String, Object> response = restTemplate.postForObject(
                RECAPTCHA_VERIFY_URL,
                request,
                Map.class
            );
            
            if (response == null) {
                logger.error("ReCAPTCHA verification failed: null response from Google");
                return false;
            }
            
            boolean success = (Boolean) response.get("success");
            if (!success) {
                List<String> errorCodes = (List<String>) response.get("error-codes");
                logger.warn("ReCAPTCHA verification failed with error codes: {}", errorCodes);
                
                // Log specific error details
                if (errorCodes != null) {
                    for (String errorCode : errorCodes) {
                        switch (errorCode) {
                            case "missing-input-secret":
                                logger.error("The secret parameter is missing");
                                break;
                            case "invalid-input-secret":
                                logger.error("The secret parameter is invalid or malformed");
                                break;
                            case "missing-input-response":
                                logger.error("The response parameter is missing");
                                break;
                            case "invalid-input-response":
                                logger.error("The response parameter is invalid or malformed");
                                break;
                            case "bad-request":
                                logger.error("The request is invalid or malformed");
                                break;
                            case "timeout-or-duplicate":
                                logger.error("The response is no longer valid: either is too old or has been used previously");
                                break;
                            default:
                                logger.error("Unknown error code: {}", errorCode);
                        }
                    }
                }
            } else {
                logger.info("ReCAPTCHA verification successful");
            }
            
            return success;
        } catch (Exception e) {
            logger.error("ReCAPTCHA verification failed with exception: {}", e.getMessage(), e);
            return false;
        }
    }
} 