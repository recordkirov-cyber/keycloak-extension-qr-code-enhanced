package com.codgin.keycloak.qrauth.auth;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import com.codgin.keycloak.qrauth.QrUtils;

public class TotpThenQrAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ext-totp-then-qr-login";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> properties = new ArrayList<ProviderConfigProperty>(QrUtils.configProperties);

    static {
        ProviderConfigProperty emailFallbackProperty = new ProviderConfigProperty();
        emailFallbackProperty.setName("send.email.fallback");
        emailFallbackProperty.setLabel("Send Email Fallback");
        emailFallbackProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emailFallbackProperty.setHelpText("Enable sending QR code via email as fallback option. Email fallback only works when authenticator knows the user (after username/password step)." );
        emailFallbackProperty.setDefaultValue(true);
        properties.add(emailFallbackProperty);

        ProviderConfigProperty emailSubjectProperty = new ProviderConfigProperty();
        emailSubjectProperty.setName("email.subject");
        emailSubjectProperty.setLabel("Email Subject");
        emailSubjectProperty.setType(ProviderConfigProperty.STRING_TYPE);
        emailSubjectProperty.setHelpText("Subject for the QR code email");
        emailSubjectProperty.setDefaultValue("Login with QR Code");
        properties.add(emailSubjectProperty);

        ProviderConfigProperty emailPrefixCut = new ProviderConfigProperty();
        emailPrefixCut.setName("email.prefixcut");
        emailPrefixCut.setLabel("Email Prefix2Cut");
        emailPrefixCut.setType(ProviderConfigProperty.STRING_TYPE);
        emailPrefixCut.setHelpText("Prefixes (sep - ;) cutoff if email startwith it");
        emailPrefixCut.setDefaultValue("");
        properties.add(emailPrefixCut);
    }

    @Override
    public void close() {
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new TotpThenQrAuthenticator();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getDisplayType() {
        return "TOTP then QR Code Sign In";
    }

    @Override
    public String getReferenceCategory() {
        return "second-factor";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return properties;
    }

    @Override
    public String getHelpText() {
        return "Two-factor authentication: TOTP code first, then QR code verification on another device.";
    }

}