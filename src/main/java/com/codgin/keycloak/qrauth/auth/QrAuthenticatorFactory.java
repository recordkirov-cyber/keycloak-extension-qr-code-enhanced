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

public class QrAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ext-qr-code-login";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> properties = new ArrayList<ProviderConfigProperty>(QrUtils.configProperties);
    
    static {
        // Add email fallback configuration properties
        ProviderConfigProperty emailFallbackProperty = new ProviderConfigProperty();
        emailFallbackProperty.setName("send.email.fallback");
        emailFallbackProperty.setLabel("Send Email Fallback");
        emailFallbackProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emailFallbackProperty.setHelpText("Enable sending QR code via email as fallback option. Email fallback only works when authenticator knows the user (after username/password step).");
        emailFallbackProperty.setDefaultValue(false);
        properties.add(emailFallbackProperty);
        
        ProviderConfigProperty emailSubjectProperty = new ProviderConfigProperty();
        emailSubjectProperty.setName("email.subject");
        emailSubjectProperty.setLabel("Email Subject");
        emailSubjectProperty.setType(ProviderConfigProperty.STRING_TYPE);
        emailSubjectProperty.setHelpText("Subject for the QR code email");
        emailSubjectProperty.setDefaultValue("Login with QR Code");
        properties.add(emailSubjectProperty);
    }


    @Override
    public void close() {
    }

    @Override
    public Authenticator create(KeycloakSession arg0) {
        return new QrAuthenticator();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope arg0) {
    }

    @Override
    public void postInit(KeycloakSessionFactory arg0) {
    }

    @Override
    public String getDisplayType() {
        return "QR Code Sign In";
    }

    @Override
    public String getReferenceCategory() {
        return null;
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
        return "Sign in using another device by scanning a QR code.";
    }
    
}
