package com.hadleyso.keycloak.qrauth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.hadleyso.keycloak.qrauth.token.QrAuthenticatorActionToken;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class QrAuthenticator implements Authenticator {

    @Override
    public void close() {
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        log.info("QrAuthenticator.action");
        return;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        log.info("QrAuthenticator.authenticate");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        UserModel user = null;

        log.info("QrAuthenticator.action 1");
        if (authSession != null) {
            log.info("QrAuthenticator.action 2");
            // Retrieve the note by key
            String authOkUserId = authSession.getAuthNote(QrUtils.AUTHENTICATED_USER_ID);
            log.info("QrAuthenticator.action 3");
            if (authOkUserId != null) {
                log.info("QrAuthenticator.action 4");
                user = session.users().getUserById(realm, authOkUserId);
            } 
        } 
        log.info("QrAuthenticator.action 5");
        if (user != null) {
            log.info("QrAuthenticator.action 6");
            // Attach the user to the flow
            context.setUser(user);

            // Mark the flow as successful
            context.success();
            return;
        }


        // NOT LOGGED IN

        // Create token and convert to link
        QrAuthenticatorActionToken token = QrUtils.createActionToken(context);
        String link = QrUtils.linkFromActionToken(context.getSession(), context.getRealm(), token);

        // Get execution ID for auto-refresh form
        String execId = context.getExecution().getId();

        // Show ftl template page with QR code
        context.forceChallenge(
            context.form()
                .setAttribute("QRauthExecId", execId)
                .setAttribute("QRauthToken", link)
                .createForm("login-qr-code.ftl")
        );
    }

    @Override
    public boolean configuredFor(KeycloakSession arg0, RealmModel arg1, UserModel arg2) {
        return true;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession arg0, RealmModel arg1, UserModel arg2) {
    }
    
}
