package com.codgin.keycloak.qrauth.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
//import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;

import com.codgin.keycloak.qrauth.QrUtils;

import lombok.extern.jbosslog.JBossLog;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

@JBossLog
public class TotpThenQrAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(TotpThenQrAuthenticator.class);

    // Authentication session notes
    private static final String TOTP_VALIDATED = "TOTP_VALIDATED";
    private static final String TOTP_ERROR_MESSAGE = "TOTP_ERROR_MESSAGE";
    private static final String SESSION_INVALID = "SESSION_INVALID";

    private static final String SEND_EMAIL_FALLBACK_CONFIG = "send.email.fallback";
    private static final String EMAIL_SUBJECT_CONFIG = "email.subject";
    private static final String EMAIL_TEMPLATE = "email-verification-with-code.ftl";

    @Override
    public void close() {
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        log.debug("TotpThenQrAuthenticator.action");
        // Action is handled in authenticate() method
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        log.debug("TotpThenQrAuthenticator.authenticate");

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        final AuthenticationSessionModel authSession = context.getAuthenticationSession();
        final KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        // Check if this is form submission with TOTP code
        String totp = context.getHttpRequest().getDecodedFormParameters().getFirst("totp");
        log.debugf("TotpThenQrAuthenticator.authenticate - totp from form: %s", totp);
        
        if (totp != null && !totp.isEmpty()) {
            // This is TOTP form submission
            log.debug("TotpThenQrAuthenticator.authenticate - processing TOTP submission");

            if (isUserDisabledByBruteForce(context, user)) {
                log.debug("TotpThenQrAuthenticator.authenticate - user disabled by brute force");
                authSession.setAuthNote(TOTP_ERROR_MESSAGE, "Your account is temporarily disabled because of too many failed login attempts.");
                showTotpForm(context);
                return;
            }

            boolean valid = validateTotp(context, totp);
            log.debugf("TotpThenQrAuthenticator.authenticate - TOTP validation result: %b", valid);
            
            if (valid) {
                // TOTP valid, clear brute-force state, mark as validated and proceed to QR phase
                log.debug("TotpThenQrAuthenticator.authenticate - TOTP valid, clearing brute force state");
                clearBruteForceState(context, user);
                log.debug("TotpThenQrAuthenticator.authenticate - TOTP valid, setting TOTP_VALIDATED");
                authSession.setAuthNote(TOTP_VALIDATED, "true");
                log.debugf("TotpThenQrAuthenticator.authenticate - TOTP_VALIDATED set, will show QR code");
                // Continue to QR code phase by re-running authenticate logic below
            } else {
                // TOTP invalid, register failed attempt and show error
                log.debug("TotpThenQrAuthenticator.authenticate - TOTP invalid");
                recordFailedLoginAttempt(context, user);
                if (isUserDisabledByBruteForce(context, user)) {
                    authSession.setAuthNote(TOTP_ERROR_MESSAGE, "Your account is temporarily disabled because of too many failed login attempts.");
                } else {
                    authSession.setAuthNote(TOTP_ERROR_MESSAGE, "Invalid TOTP code");
                }
                showTotpForm(context);
                return;
            }
        }

        // Check if user is already authenticated (has active session)
        AppAuthManager authManager = new AppAuthManager();
        AuthenticationManager.AuthResult authResult = authManager.authenticateIdentityCookie(session, realm);
        if (authResult != null) {
            UserModel currentUser = getUserFromAuthResult(authResult);
            if (currentUser != null) {
                if (logger.isTraceEnabled()) {
                    logger.tracef("User '%s' '%s' already authenticated, attaching to flow '%s'", currentUser.getId(), currentUser.getUsername(), context.toString());
                }
                context.setUser(currentUser);
                context.success();
                return;
            }
        }

        // Check if user is set
        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        // Check if TOTP is already validated
        String totpValidated = authSession.getAuthNote(TOTP_VALIDATED);
        log.debugf("TotpThenQrAuthenticator.authenticate - TOTP_VALIDATED note: %s", totpValidated);
        
        if ("true".equals(totpValidated)) {
            // TOTP validated, now handle QR code phase
            log.debug("TotpThenQrAuthenticator.authenticate - TOTP validated, proceeding to QR phase");

            // Check if QR authentication is already complete
            String authOkUserId = authSession.getAuthNote(QrUtils.AUTHENTICATED_USER_ID);
            if (authOkUserId != null) {
                UserModel qrUser = session.users().getUserById(realm, authOkUserId);
                if (qrUser != null && qrUser.getId().equals(user.getId())) {
                    // QR authentication successful for the same user
                    context.setUser(qrUser);
                    QrUtils.handleACR(config, context);
                    QrUtils.handleCredTransfer(config, context);
                    context.success();
                    return;
                }
            }

            // Check for rejection
            String reject = authSession.getAuthNote(QrUtils.REJECT);
            if (reject == QrUtils.REJECT) {
                if (logger.isTraceEnabled()) {
                    logger.tracef("Flow '%s' was rejected by remote by user", context.toString());
                }
                QrUtils.rejectedBruteForce(context);
                context.clearUser();
                context.failure(AuthenticationFlowError.ACCESS_DENIED);
                return;
            }

            // Check for timeout
            if (QrUtils.timeoutPassed(context)) {
                if (logger.isTraceEnabled()) {
                    logger.tracef("Flow '%s' has expired", context.toString());
                }
                context.failure(AuthenticationFlowError.EXPIRED_CODE);
                return;
            }

            // Show QR code for second factor
            showQrCode(context);
        } else {
            // TOTP not yet validated, show TOTP form
            log.debug("TotpThenQrAuthenticator.authenticate - TOTP not validated, showing TOTP form");
            showTotpForm(context);
        }
    }

    private void showTotpForm(AuthenticationFlowContext context) {
        log.debug("TotpThenQrAuthenticator.showTotpForm");

        UserModel user = context.getUser();
        if (user == null) {
            // Show error - user not set
            Response challenge = context.form()
                .setError("totpNotConfigured", "User not found")
                .createForm("totp-then-qr-totp.ftl");
            context.challenge(challenge);
            return;
        }

        // Check if user has TOTP configured
        if (!isTotpConfigured(user)) {
            // Show error - TOTP not configured
            Response challenge = context.form()
                .setError("totpNotConfigured", "TOTP authentication is not configured for this user. Please configure TOTP first.")
                .createForm("totp-then-qr-totp.ftl");
            context.challenge(challenge);
            return;
        }

        if (isUserDisabledByBruteForce(context, user)) {
            context.getAuthenticationSession().setAuthNote(TOTP_ERROR_MESSAGE, "Your account is temporarily disabled because of too many failed login attempts.");
        }

        // Prepare form data
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add("username", user.getUsername());

        // Check for error message
        String errorMessage = context.getAuthenticationSession().getAuthNote(TOTP_ERROR_MESSAGE);
        if (errorMessage != null) {
            formData.add("totpError", errorMessage);
            context.getAuthenticationSession().removeAuthNote(TOTP_ERROR_MESSAGE);
        }

        // Create form
        LoginFormsProvider form = context.form();
        form.setAttribute("executionId", context.getExecution().getId());
        form.setAttribute("login", formData);
        for (String key : formData.keySet()) {
            form.setAttribute(key, formData.getFirst(key));
        }
        form.setFormData(formData);

        Response challenge = form.createForm("totp-then-qr-totp.ftl");
        context.challenge(challenge);
    }

    private void showQrCode(AuthenticationFlowContext context) {
        log.debug("TotpThenQrAuthenticator.showQrCode");

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        final AuthenticationSessionModel authSession = context.getAuthenticationSession();
        final KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        // Check if already made
        String link = authSession.getAuthNote(QrUtils.NOTE_QR_LINK);

        if (link == null) {
            // Create token and convert to link - THIS STARTS THE TOKEN TTL
            //long tokenCreationTime = System.currentTimeMillis();
            //log.debugf("TotpThenQrAuthenticator.showQrCode - Creating new QR token at %d (after TOTP validation)", tokenCreationTime);
            
            String token = QrUtils.createPublicToken(context, QrUtils.transferAcrEnabled(config));
            if (token == null) {
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                return;
            }
            link = QrUtils.linkFromActionToken(session, realm, token, false);
            authSession.setAuthNote(QrUtils.NOTE_QR_LINK, link);
            authSession.setAuthNote(QrUtils.BRUTE_FORCE_USER_ID, user.getId());
            if (logger.isTraceEnabled()) {
                logger.tracef("Created new token with link - token: '%s;", token);
            }

            // Set QR timeout starting from now (when QR is shown to user)
            QrUtils.setQrTimeout(context);
        } else {
            log.debugf("TotpThenQrAuthenticator.showQrCode - Reusing existing QR link (token already created)");
            if (authSession.getAuthNote(QrUtils.BRUTE_FORCE_USER_ID) == null && user != null) {
                authSession.setAuthNote(QrUtils.BRUTE_FORCE_USER_ID, user.getId());
            }
        }

        String qrImageData = QrUtils.qrCode(link);

        // Get execution ID for auto-refresh form and TabID
        String execId = context.getExecution().getId();
        String tabId = authSession.getTabId();

        // Get refresh rate
        int refreshRate = 150;
        if (config != null) {
            refreshRate = Integer.valueOf(config.getConfig().get("refresh.rate"));
            if (refreshRate < 0) {
                refreshRate = 0;
            }
        }

        // Get alignment
        String alignment = "Center";
        if (config != null) {
            alignment = config.getConfig().get("display.alignment");
            if (alignment == null)
                alignment = "Center";
        }

        if (logger.isTraceEnabled()) {
            logger.tracef("Serving session '%s' with tabId '%s' with token in link: '%s;", execId, tabId, link);
        }

        boolean sendEmailFallback = false;
        if (config != null) {
            sendEmailFallback = Boolean.parseBoolean(config.getConfig().get(SEND_EMAIL_FALLBACK_CONFIG));
        }

        if (sendEmailFallback && context.getUser() != null) {
            sendEmailFallback(context, link);
        }

        // Show ftl template page with QR code for second factor
        context.challenge(
                context.form()
                        .setAttribute("QRauthExecId", execId)
                        .setAttribute("QRauthToken", link)
                        .setAttribute("tabId", tabId)
                        .setAttribute("refreshRate", refreshRate)
                        .setAttribute("alignment", alignment)
                        .setAttribute("QRauthImage", qrImageData)
                        .setAttribute("isSecondFactor", true) // Indicate this is second factor
                        .setAttribute("sendEmailFallback", sendEmailFallback)
                        .setAttribute("username", user.getUsername())
                        .setAttribute("userEmail", user.getEmail())
                        .createForm("totp-then-qr-scan.ftl"));
    }

    private boolean isUserDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
        BruteForceProtector protector = context.getSession().getProvider(BruteForceProtector.class);
        if (protector == null || user == null) {
            return false;
        }

        RealmModel realm = context.getRealm();
        boolean disabled = protector.isTemporarilyDisabled(context.getSession(), realm, user)
                || protector.isPermanentlyLockedOut(context.getSession(), realm, user);

        if (disabled) {
            context.getAuthenticationSession().setAuthNote(SESSION_INVALID, "true");
            return true;
        }

        context.getAuthenticationSession().removeAuthNote(SESSION_INVALID);
        return false;
    }

    private void recordFailedLoginAttempt(AuthenticationFlowContext context, UserModel user) {
        BruteForceProtector protector = context.getSession().getProvider(BruteForceProtector.class);
        invokeBruteForceProtectorMethod(protector, "failedLogin", context, user);
    }

    private void clearBruteForceState(AuthenticationFlowContext context, UserModel user) {
        BruteForceProtector protector = context.getSession().getProvider(BruteForceProtector.class);
        invokeBruteForceProtectorMethod(protector, "successfulLogin", context, user);
        context.getAuthenticationSession().removeAuthNote(SESSION_INVALID);
    }

    private void invokeBruteForceProtectorMethod(BruteForceProtector protector, String methodName,
            AuthenticationFlowContext context, UserModel user) {
        if (protector == null || user == null) {
            return;
        }

        RealmModel realm = context.getRealm();
        ClientConnection connection = context.getSession().getContext().getConnection();
        UriInfo uriInfo = context.getSession().getContext().getUri();

        try {
            java.lang.reflect.Method method = protector.getClass().getMethod(methodName,
                    RealmModel.class, UserModel.class, ClientConnection.class, UriInfo.class, String.class);
            method.invoke(protector, realm, user, connection, uriInfo, "otp");
        } catch (NoSuchMethodException e) {
            try {
                java.lang.reflect.Method fallback = protector.getClass().getMethod(methodName,
                        RealmModel.class, UserModel.class, ClientConnection.class, UriInfo.class);
                fallback.invoke(protector, realm, user, connection, uriInfo);
            } catch (Exception ex) {
                logger.errorf(ex, "Failed to invoke fallback brute-force method %s", methodName);
            }
        } catch (Exception e) {
            logger.errorf(e, "Failed to invoke brute-force method %s", methodName);
        }
    }

    private boolean validateTotp(AuthenticationFlowContext context, String totp) {
        log.debug("TotpThenQrAuthenticator.validateTotp");

        UserModel user = context.getUser();
        if (user == null) {
            log.warn("TotpThenQrAuthenticator.validateTotp - user is null");
            return false;
        }

        // Get user's TOTP credentials
        List<CredentialModel> otpCredentials = user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .collect(Collectors.toList());

        log.debugf("TotpThenQrAuthenticator.validateTotp - found %d OTP credentials", otpCredentials.size());

        if (otpCredentials.isEmpty()) {
            log.warn("TotpThenQrAuthenticator.validateTotp - no OTP credentials found");
            return false;
        }

        // Use the built-in OTP credential provider for validation
        try {
            OTPCredentialProvider provider = (OTPCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);

            if (provider != null) {
                // Check all TOTP credentials until one validates successfully
                for (CredentialModel credential : otpCredentials) {
                    boolean result = provider.isValid(context.getRealm(), user,
                        new UserCredentialModel(credential.getId(), OTPCredentialModel.TYPE, totp));
                    log.debugf("TotpThenQrAuthenticator.validateTotp - credential %s validation result: %b", credential.getId(), result);
                    if (result) {
                        return true;
                    }
                }
                // None of the credentials validated
                return false;
            } else {
                log.warn("TotpThenQrAuthenticator.validateTotp - OTPCredentialProvider is null");
            }
        } catch (Exception e) {
            log.errorf("TotpThenQrAuthenticator.validateTotp - error validating TOTP: %s", e.getMessage());
        }

        return false;
    }

    private boolean isTotpConfigured(UserModel user) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .findFirst()
            .isPresent();
    }

    private void sendEmailFallback(AuthenticationFlowContext context, String qrLink) {
        try {
            UserModel user = context.getUser();
            if (user == null || user.getEmail() == null || user.getEmail().isEmpty()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("User or user email is null/empty, skipping email fallback");
                }
                return;
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();

            String emailSubject = "Login with QR Code";
            String emailTemplate = EMAIL_TEMPLATE;

            if (config != null && config.getConfig().get(EMAIL_SUBJECT_CONFIG) != null) {
                emailSubject = config.getConfig().get(EMAIL_SUBJECT_CONFIG);
            }

            final AuthenticationSessionModel authSession = context.getAuthenticationSession();
            String userAgent = authSession.getAuthNote(QrUtils.ORIGIN_UA_AGENT);
            String os = authSession.getAuthNote(QrUtils.ORIGIN_UA_OS);
            String device = authSession.getAuthNote(QrUtils.ORIGIN_UA_DEVICE);

            String ipAddress = null;
            if (context.getSession().getContext().getConnection() != null) {
                ipAddress = context.getSession().getContext().getConnection().getRemoteAddr();
            }

            StringBuilder metadataBuilder = new StringBuilder();
            metadataBuilder.append(qrLink);
            metadataBuilder.append("<br><br> --- Login Details --- <br>");
            if (context.getSession().getContext().getClient() != null) {
                metadataBuilder.append("Client ID: ").append(context.getSession().getContext().getClient().getClientId()).append("<br>");
            }
            if (ipAddress != null) {
                metadataBuilder.append("IP Address: ").append(ipAddress).append("<br>");
            }
            if (os != null) {
                metadataBuilder.append("Operating System: ").append(os).append("<br>");
            }
            if (device != null) {
                metadataBuilder.append("Device: ").append(device).append("<br>");
            }
            if (userAgent != null) {
                metadataBuilder.append("Browser: ").append(userAgent).append("<br>");
            }

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("code", metadataBuilder.toString());

            EmailTemplateProvider emailProvider = context.getSession().getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(context.getRealm());
            emailProvider.setUser(user);
            emailProvider.send(emailSubject, emailTemplate, attributes);

            if (logger.isDebugEnabled()) {
                logger.debugf("Sent QR code email to user %s", user.getEmail());
            }
        } catch (EmailException e) {
            logger.error("Failed to send QR code email", e);
        } catch (Exception e) {
            logger.error("Unexpected error while sending QR code email", e);
        }
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // This authenticator is configured for users who have TOTP configured
        return isTotpConfigured(user);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    /**
     * Gets the user from AuthResult with compatibility for both Keycloak 26.4 and 26.5
     * In 26.5, AuthResult is a record with user() method, while in 26.4 it's a regular class with getUser() method
     */
    private UserModel getUserFromAuthResult(AuthenticationManager.AuthResult authResult) {
        try {
            // Try using the new method available in Keycloak 26.5 (record accessor)
            java.lang.reflect.Method userMethod = authResult.getClass().getMethod("user");
            return (UserModel) userMethod.invoke(authResult);
        } catch (Exception e) {
            try {
                // Fallback to deprecated method for older versions
                java.lang.reflect.Method getUserMethod = authResult.getClass().getMethod("getUser");
                return (UserModel) getUserMethod.invoke(authResult);
            } catch (Exception ex) {
                // If both methods fail, re-throw the original exception
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException("Failed to get user from AuthResult", e);
                }
            }
        }
    }
}