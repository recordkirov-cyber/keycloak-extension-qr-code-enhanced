<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "title">
        ${msg("doTotpThenQrLogin")}
    <#elseif section = "header">
        ${msg("doTotpThenQrLogin")}
    <#elseif section = "form">
        <div class="alert alert-info">
            <span class="kc-feedback-text">${msg("totpThenQrInfo")}</span>
        </div>

        <#if totpError??>
            <div class="alert alert-error">
                <span class="kc-feedback-text">${totpError}</span>
            </div>
        </#if>

        <form id="kc-totp-qr-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="totp" class="${properties.kcLabelClass!}">${msg("totpThenQrTotpLabel")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="totp" name="totp" class="${properties.kcInputClass!}" autocomplete="off" autofocus />
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input type="hidden" name="authenticationExecution" value="${executionId}" />
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>