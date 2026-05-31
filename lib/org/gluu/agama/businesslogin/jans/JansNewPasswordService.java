package org.gluu.agama.businesslogin.jans;
import io.jans.agama.engine.service.FlowService;
import io.jans.as.common.model.common.User;
import io.jans.as.server.service.AuthenticationService;
import io.jans.as.server.service.UserService;
import io.jans.orm.model.base.CustomObjectAttribute;
import io.jans.service.CacheService;
import io.jans.service.cdi.util.CdiUtil;
import org.gluu.agama.businesslogin.NewPasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jans.agama.engine.script.LogUtils;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Base64;
import java.util.stream.Collectors;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

public class JansNewPasswordService extends NewPasswordService {

    private static final Logger logger = LoggerFactory.getLogger(FlowService.class);
    public static final String JANS_STATUS = "jansStatus";
    public static final String INACTIVE = "inactive";
    public static final String ACTIVE = "active";
    public static final String CACHE_PREFIX = "lock_user_";
    private static final String PHONE_NUMBER = "telephoneNumber";
    private static final String LANG = "lang";
    private static final String PHONE_VERIFIED = "phoneNumberVerified";
    private static final int OTP_LENGTH = 6;
    private static final int OTP_CODE_LENGTH = 6;
    private static AuthenticationService authenticationService = CdiUtil.bean(AuthenticationService.class);
    private static UserService userService = CdiUtil.bean(UserService.class);
    private static CacheService cacheService = CdiUtil.bean(CacheService.class);
    private String INVALID_LOGIN_COUNT_ATTRIBUTE = "jansCountInvalidLogin";
    private int DEFAULT_MAX_LOGIN_ATTEMPT = 3;
    private int DEFAULT_LOCK_EXP_TIME = 180;

    private HashMap<String, String> flowConfig;
    private static final Map<String, String> otpStore   = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Map<String, Long>   otpExpiry  = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Map<String, long[]> sendCounts = new java.util.concurrent.ConcurrentHashMap<>();

    public JansNewPasswordService(HashMap config) {
        logger.info("Flow config provided is  {}.", config);
        flowConfig = config;
        DEFAULT_MAX_LOGIN_ATTEMPT = flowConfig.get("maxLoginAttempt") != null ? flowConfig.get("maxLoginAttempt") : DEFAULT_MAX_LOGIN_ATTEMPT;
        DEFAULT_LOCK_EXP_TIME = flowConfig.get("lockExpTime") != null ? flowConfig.get("lockExpTime") : DEFAULT_LOCK_EXP_TIME;
    }

    public JansNewPasswordService() {
    }

    @Override
    public boolean validate(String username, String password) {
        // Safety net: only business accounts can authenticate via this flow.
        // Personal users fat-fingering credentials here get the same surface as wrong password — no leak.
        if (!isBusinessAccount(username)) {
            logger.warn("Business login rejected — not a business account: {}", username);
            return false;
        }
        logger.info("Validating user credentials.");
        boolean hasLogin = authenticationService.authenticate(username, password);
        if (hasLogin && Boolean.valueOf(flowConfig.get("ENABLE_ACCOUNT_LOCK"))) {
            logger.info("Credentials are valid and user account locked feature is activated");
            User currentUser = userService.getUser(username);
            userService.setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, 0);
            userService.updateUser(currentUser);
            logger.info("Invalid login count reset to zero for {} .", username);
        }
        return hasLogin;
    }

    @Override
    public String lockAccount(String username) {
        // Don't touch personal accounts via the business flow.
        // Returning null (vs. a specific message) keeps the UI surface identical
        // to "username doesn't exist" — no information leak.
        if (!isBusinessAccount(username)) {
            LogUtils.log("Business lockAccount skipped — not a business account: %", username);
            return null;
        }
        User currentUser = userService.getUser(username);
        if (currentUser == null) {
            LogUtils.log("User % not found. Cannot lock account.", username);
            return null;
        }
        int currentFailCount = 1;
        String invalidLoginCount = getCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE);
        if (invalidLoginCount != null) {
            currentFailCount = Integer.parseInt(invalidLoginCount) + 1;
        }
        String currentStatus = getCustomAttribute(currentUser, JANS_STATUS);
        logger.info("Current user status is: {}", currentStatus);
        if (currentFailCount < DEFAULT_MAX_LOGIN_ATTEMPT) {
            int remainingCount = DEFAULT_MAX_LOGIN_ATTEMPT - currentFailCount;
            logger.info("Remaining login count: {} for user {}", remainingCount, username);
            if (remainingCount > 0 && currentStatus == "active") {
                setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, String.valueOf(currentFailCount));
                logger.info("{}  more attempt(s) before account is LOCKED!", remainingCount);
            }
            return "You have " + remainingCount + " more attempt(s) before your account is locked.";
        }
        if (currentFailCount >= DEFAULT_MAX_LOGIN_ATTEMPT && currentStatus == "active") {
            logger.info("Locking {} account for {} seconds.", username, DEFAULT_LOCK_EXP_TIME);
            String object_to_store = "{'locked': 'true'}";
            setCustomAttribute(currentUser, JANS_STATUS, INACTIVE);
            cacheService.put(DEFAULT_LOCK_EXP_TIME, CACHE_PREFIX + username, object_to_store);
            return "Your account have been locked.";
        }
        if (currentFailCount >= DEFAULT_MAX_LOGIN_ATTEMPT && currentStatus == "inactive") {
            logger.info("User {} account is already locked. Checking if we can unlock", username);
            String cache_object = cacheService.get(CACHE_PREFIX + username);
            if (cache_object == null) {
                logger.info("Unlocking user {} account", username);
                setCustomAttribute(currentUser, JANS_STATUS, ACTIVE);
                setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, "0");
                return "Your account  is now unlock. Try login ";
            }

        }
        return null;
    }

    private boolean isBusinessAccount(String username) {
        try {
            User user = userService.getUser(username);
            if (user == null) return false;
            Object orgVal = user.getAttribute("businessName", true, false);
            return orgVal != null && !orgVal.toString().trim().isEmpty();
        } catch (Exception e) {
            logger.error("isBusinessAccount lookup failed for {}: {}", username, e.getMessage(), e);
            return false;
        }
    }

    private String getCustomAttribute(User user, String attributeName) {
        CustomObjectAttribute customAttribute = userService.getCustomAttribute(user, attributeName);
        if (customAttribute != null) {
            return customAttribute.getValue();
        }
        return null;
    }

    private User setCustomAttribute(User user, String attributeName, String value) {
        userService.setCustomAttribute(user, attributeName, value);
        return userService.updateUser(user);
    }

    public boolean isPhoneVerified(String username) {
        try {
            User user = userService.getUser(username);
            if (user == null) return false;

            Object val = user.getAttribute("phoneNumberVerified", true, false);
            return val != null && Boolean.parseBoolean(val.toString());
        } catch (Exception e) {
            logger.error("Error checking phone verification for {}: {}", username, e.getMessage(), e);
            return false;
        }
    }

    public boolean isPhoneUnique(String username, String phone) {
        // Business accounts intentionally allow shared phone numbers
        // (one personal user can own many businesses, all reachable on the same phone).
        // The method is preserved for compatibility with the existing flow Call block.
        return true;
    }


    public String getPhoneNumber(String username) {
        try {
            User user = userService.getUser(username);
            if (user == null) return null;
            Object phone = user.getAttribute(PHONE_NUMBER, true, false);
            return phone != null ? phone.toString() : null;
        } catch (Exception e) {
            logger.error("Error fetching phone number for {}: {}", username, e.getMessage(), e);
            return null;
        }
    }


    public String markPhoneAsVerified(String username, String phone) {
        try {
            User user = userService.getUser(username);
            if (user == null) {
                logger.warn("User {} not found while marking phone verified", username);
                return "User not found.";
            }

            // Set the phone number and mark it as verified
            user.setAttribute(PHONE_NUMBER, phone);
            user.setAttribute("phoneNumberVerified", Boolean.TRUE);
            userService.updateUser(user);

            logger.info("Phone {} verified and updated for user {}", phone, username);
            return "Phone " + phone + " verified successfully for user " + username;
        } catch (Exception e) {
            logger.error("Error marking phone verified for {}: {}", username, e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }

    private String generateSMSOtpCode(int codeLength) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

     public String sendOTPCode(String username, String phone, String verificationMethod) {
        try {
            // Per-phone send rate-limit — defense against SMS bombing / cost abuse.
            if (!canSendOTP(phone)) {
                logger.warn("OTP send rate-limited for phone {}", phone);
                return null;
            }

            // Get user preferred language from profile
            User user = userService.getUser(username);
            String lang = null;
            if (user != null) {
                Object val = user.getAttribute(LANG, true, false);
                if (val != null) {
                    lang = val.toString().toLowerCase();
                }
            }
            if (lang == null || lang.isEmpty()) {
                lang = "en";
            }

            // Generate OTP, store with TTL
            String otpCode = generateSMSOtpCode(OTP_LENGTH);
            otpStore.put(phone, otpCode);
            otpExpiry.put(phone, System.currentTimeMillis() + otpTtlMs());
            logger.info("OTP generated for phone={}", phone);

            // Localized SMS body
            Map<String, String> messages = new HashMap<>();
            messages.put("ar", "رمز التحقق OTP الخاص بك من Phi Wallet هو " + otpCode + ". لا تشاركه مع أي شخص.");
            messages.put("en", "Your Phi Wallet OTP is " + otpCode + ". Do not share it with anyone.");
            messages.put("es", "Tu código de Phi Wallet es " + otpCode + ". No lo compartas con nadie.");
            messages.put("fr", "Votre code Phi Wallet est " + otpCode + ". Ne le partagez avec personne.");
            messages.put("id", "Kode Phi Wallet Anda adalah " + otpCode + ". Jangan bagikan kepada siapa pun.");
            messages.put("pt", "O seu código da Phi Wallet é " + otpCode + ". Não o partilhe com ninguém.");
            String message = messages.getOrDefault(lang, messages.get("en"));

            // Twilio REST credentials (shared by SMS and WhatsApp branches)
            String accountSid = flowConfig.get("ACCOUNT_SID");
            String authToken  = flowConfig.get("AUTH_TOKEN");
            String credentials = Base64.getEncoder().encodeToString(
                (accountSid + ":" + authToken).getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            String twilioUrl = "https://api.twilio.com/2010-04-01/Accounts/" + accountSid + "/Messages.json";

            // Branch on user's verification method choice.
            // Both branches call Twilio's REST API directly via java.net.http — no SDK needed.
            boolean isWhatsApp = "whatsapp".equalsIgnoreCase(verificationMethod);

            if (isWhatsApp) {
                String waFromNumber = flowConfig.get("FROM_NUMBER_WHATSAPP");
                if (waFromNumber == null || waFromNumber.trim().isEmpty()) {
                    logger.error("FROM_NUMBER_WHATSAPP not configured");
                    return null;
                }
                String contentSid = getWhatsAppContentSid(lang);
                if (contentSid == null || contentSid.trim().isEmpty()) {
                    logger.error("No WhatsApp content SID for lang={}", lang);
                    return null;
                }

                String waFrom = "whatsapp:" + waFromNumber;
                String waTo   = "whatsapp:" + phone;
                String encodedTo    = java.net.URLEncoder.encode(waTo, "UTF-8");
                String encodedFrom  = java.net.URLEncoder.encode(waFrom, "UTF-8");
                String encodedSid   = java.net.URLEncoder.encode(contentSid, "UTF-8");
                String encodedVars  = java.net.URLEncoder.encode("{\"1\":\"" + otpCode + "\"}", "UTF-8");
                String formBody = "To=" + encodedTo + "&From=" + encodedFrom + "&ContentSid=" + encodedSid + "&ContentVariables=" + encodedVars;

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(twilioUrl))
                    .header("Authorization", "Basic " + credentials)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();
                HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    logger.error("WhatsApp send failed: status={} body={}", response.statusCode(), response.body());
                    return null;
                }
                logger.info("WhatsApp OTP sent to {}", phone);
                return phone;
            } else {
                // SMS via raw HTTP — avoids Twilio SDK + its Apache HttpClient 5 dependency
                String fromNumber = getFromNumberForPhone(phone);
                if (fromNumber == null || fromNumber.trim().isEmpty()) {
                    logger.error("FROM_NUMBER null/empty for phone {}", phone);
                    return null;
                }

                String encodedTo    = java.net.URLEncoder.encode(phone, "UTF-8");
                String encodedFrom  = java.net.URLEncoder.encode(fromNumber, "UTF-8");
                String encodedBody  = java.net.URLEncoder.encode(message, "UTF-8");
                String formBody = "To=" + encodedTo + "&From=" + encodedFrom + "&Body=" + encodedBody;

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(twilioUrl))
                    .header("Authorization", "Basic " + credentials)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();
                HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    logger.error("SMS send failed: status={} body={}", response.statusCode(), response.body());
                    return null;
                }
                logger.info("SMS OTP sent to {} using sender {}", phone, fromNumber);
                return phone;
            }
        } catch (Throwable t) {
            // Throwable (not just Exception) to also catch NoClassDefFoundError
            // — surfaces as a clean null return instead of crashing the Agama engine.
            logger.error("Failed to send OTP to {}. Error class={} message={}", phone, t.getClass().getName(), t.getMessage(), t);
            return null;
        }
    }

    private String getWhatsAppContentSid(String lang) {
        String suffix = (lang != null && !lang.isEmpty()) ? lang.toUpperCase() : "EN";
        String sid = flowConfig.get("WHATSAPP_CONTENT_SID_" + suffix);
        if (sid == null || sid.trim().isEmpty()) {
            sid = flowConfig.get("WHATSAPP_CONTENT_SID_EN");
        }
        return sid;
    }

    public boolean validateOTPCode(String phone, String code) {
        try {
            String storedCode = otpStore.get(phone);
            Long   expiresAt  = otpExpiry.get(phone);
            if (storedCode == null || expiresAt == null) {
                logger.info("OTP validate phone={} result=miss", phone);
                return false;
            }
            if (System.currentTimeMillis() > expiresAt) {
                otpStore.remove(phone);
                otpExpiry.remove(phone);
                logger.info("OTP validate phone={} result=expired", phone);
                return false;
            }
            boolean ok = storedCode.equalsIgnoreCase(code);
            if (ok) {
                otpStore.remove(phone);
                otpExpiry.remove(phone);
            }
            logger.info("OTP validate phone={} result={}", phone, ok ? "ok" : "wrong");
            return ok;
        } catch (Exception ex) {
            logger.error("Error validating OTP for phone {}: {}", phone, ex.getMessage(), ex);
            return false;
        }
    }

    /**
     * Determines which FROM_NUMBER to use based on the phone number's country code.
     * Priority: 1) Countries in US_COUNTRY_CODES use FROM_NUMBER_US, 
     *          2) Countries in RESTRICTED_COUNTRY_CODES use FROM_NUMBER_RESTRICTED_COUNTRIES,
     *          3) All others use default FROM_NUMBER.
     */
    private String getFromNumberForPhone(String phone) {
        try {
            logger.info("=== getFromNumberForPhone START: phone='{}' ===", phone);
            String defaultFromNumber = flowConfig.get("FROM_NUMBER");
            String usCountryCodes = flowConfig.get("US_COUNTRY_CODES");
            String restrictedCodes = flowConfig.get("RESTRICTED_COUNTRY_CODES");
            
            logger.info("Config values - FROM_NUMBER: '{}', US_COUNTRY_CODES: '{}', RESTRICTED_CODES: '{}'", 
                       defaultFromNumber, usCountryCodes, restrictedCodes);
            
            if (defaultFromNumber == null || defaultFromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER not configured");
                return null;
            }
            
            // Parse US country codes for matching
            Set<String> usCountrySet = new HashSet<>();
            if (usCountryCodes != null && !usCountryCodes.trim().isEmpty()) {
                usCountrySet = java.util.Arrays.stream(usCountryCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            logger.info("US_COUNTRY_CODES from config: '{}' -> parsed to: {}", usCountryCodes, usCountrySet);
            
            // Parse restricted country codes for matching
            Set<String> restrictedSet = new HashSet<>();
            if (restrictedCodes != null && !restrictedCodes.trim().isEmpty()) {
                restrictedSet = java.util.Arrays.stream(restrictedCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            
            // Combine both sets for accurate country code extraction
            Set<String> allKnownCodes = new HashSet<>();
            allKnownCodes.addAll(usCountrySet);
            allKnownCodes.addAll(restrictedSet);
            logger.info("Combined allKnownCodes: {}", allKnownCodes);
            
            // Extract country code from phone number
            String countryCode = extractCountryCode(phone, allKnownCodes);
            logger.info("Phone: '{}' -> Extracted country code: '{}'", phone, countryCode);
            
            if (countryCode == null || countryCode.isEmpty()) {
                logger.info("No country code extracted, using default sender");
                return defaultFromNumber;
            }

            // Priority 1: Check if country code is in US_COUNTRY_CODES - use US-specific sender
            logger.info("Checking if country code '{}' is in US_COUNTRY_CODES: {}", countryCode, usCountrySet);
            logger.info("usCountrySet.size(): {}, contains('{}'): {}", usCountrySet.size(), countryCode, usCountrySet.contains(countryCode));
            if (usCountrySet.contains(countryCode)) {
                String usFromNumber = flowConfig.get("FROM_NUMBER_US");
                logger.info("Retrieved FROM_NUMBER_US from config: '{}'", usFromNumber);
                
                if (usFromNumber != null && !usFromNumber.trim().isEmpty()) {
                    logger.info("Using US-specific sender {} for country code {}", usFromNumber, countryCode);
                    return usFromNumber;
                }
            }

            // Priority 2: Check if country code is in restricted list
            logger.info("Checking if country code '{}' is in restricted list: {}", countryCode, restrictedSet);
            if (restrictedSet.contains(countryCode)) {
                String restrictedFromNumber = flowConfig.get("FROM_NUMBER_RESTRICTED_COUNTRIES");
                
                if (restrictedFromNumber != null && !restrictedFromNumber.trim().isEmpty()) {
                    logger.info("Using restricted sender {} for country code {}", restrictedFromNumber, countryCode);
                    return restrictedFromNumber;
                }
            }

            logger.info("No matching category found, returning default sender: {}", defaultFromNumber);
            return defaultFromNumber;
        } catch (Exception ex) {
            logger.error("Error in getFromNumberForPhone: {}", ex.getMessage(), ex);
            return flowConfig.get("FROM_NUMBER");
        }
    }

    /**
     * Extract country code from phone number by matching against known codes.
     * Returns 1-digit code "1" or 2-3 digit country code.
     */
    private String extractCountryCode(String phone, Set<String> knownCodes) {
        logger.info("extractCountryCode: input phone='{}'", phone);
        
        if (phone == null || phone.trim().isEmpty()) {
            return null;
        }

        String cleaned = phone.startsWith("+") ? phone.substring(1) : phone;
        logger.info("extractCountryCode: after removing +, cleaned='{}'", cleaned);
        
        if (cleaned.length() < 2) {
            return null;
        }

        // Handle code "1" first (US/Canada and territories)
        boolean isDigit = cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1));
        logger.info("extractCountryCode: startsWith('1')? {}, length > 1? {}, charAt(1) is digit? {}", 
                    cleaned.startsWith("1"), cleaned.length() > 1, isDigit);
        
        if (cleaned.startsWith("1") && cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1))) {
            logger.info("extractCountryCode: returning '1'");
            return "1";
        }
        
        // Try 3-digit codes ONLY if they're in our knownCodes list
        if (cleaned.length() >= 3 && knownCodes != null && !knownCodes.isEmpty()) {
            String threeDigit = cleaned.substring(0, 3);
            if (knownCodes.contains(threeDigit)) {
                return threeDigit;
            }
        }
        
        // Default: Extract 2-digit country code
        return cleaned.substring(0, 2);
    }

    // ---------------------------------------------------------------
    // Config-driven OTP knobs (defaults match business registration)
    //   OTP_TTL_SECONDS         — how long an OTP stays valid (default 600s)
    //   OTP_SEND_WINDOW_SECONDS — rolling window for per-phone send count (default 3600s)
    //   OTP_MAX_SENDS_PER_HOUR  — max sends per phone per window (default 8)
    // All optional — defaults apply if the key is missing or non-numeric.
    // ---------------------------------------------------------------

    private long configLong(String key, long defaultValue) {
        try {
            String v = flowConfig.get(key);
            if (v == null || v.trim().isEmpty()) return defaultValue;
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            logger.warn("Invalid {} in config (not a number); using default {}", key, defaultValue);
            return defaultValue;
        }
    }

    private long otpTtlMs()        { return configLong("OTP_TTL_SECONDS", 600L) * 1000L; }
    private long sendWindowMs()    { return configLong("OTP_SEND_WINDOW_SECONDS", 3600L) * 1000L; }
    private int  maxSendsPerHour() { return (int) configLong("OTP_MAX_SENDS_PER_HOUR", 8L); }

    // Per-phone rate gate. Returns false once the phone has used its quota
    // within the current window; increments the counter on success.
    private boolean canSendOTP(String phone) {
        long now = System.currentTimeMillis();
        long[] entry = sendCounts.get(phone);
        if (entry == null || now - entry[1] > sendWindowMs()) {
            entry = new long[] { 0L, now };
            sendCounts.put(phone, entry);
        }
        if (entry[0] >= maxSendsPerHour()) return false;
        entry[0]++;
        return true;
    }

}