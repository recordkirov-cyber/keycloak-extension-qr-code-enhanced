<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "title">
        ${msg("doQrCodeVerify")}
    <#elseif section = "header">
        ${msg("doQrCodeVerify")}
    <#elseif section = "form">

        <p>${msg("doQrCodeWarning")}<p>

        <ul>
            <li>OS: ${ua_os}</li>
            <li>Device: ${ua_device}</li>
            <li>Agent: ${ua_agent}</li>
        </ul>

        <a type="button" href="${approveURL}" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}">
            ${msg("doLogIn")}
        </a>
        
    </#if>
</@layout.registrationLayout>
