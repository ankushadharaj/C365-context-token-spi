package org.example.spi;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.jboss.logging.Logger;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.ArrayList;
import java.util.List;

public class CustomProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "encode-protocol-mapper";
    private static final Logger logger = Logger.getLogger(CustomProtocolMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomProtocolMapper.class);
    }

    private AuthenticationManager.AuthResult checkAuth(KeycloakSession session) {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        } else if (auth.getToken().getIssuedFor() == null || !auth.getToken().getIssuedFor().equals("compliance365-client")) {
            throw new ForbiddenException("Token is not properly issued for admin-cli");
        }
        return auth;
    }
    @Override
    public AccessToken transformAccessToken(AccessToken accessToken, ProtocolMapperModel protocolMapperModel, KeycloakSession session, UserSessionModel userSessionModel, ClientSessionContext clientSessionContext) {
        logger.info("Processing access token");
        HttpHeaders headers = (HttpHeaders) session.getContext().getRequestHeaders();

        String tenantId = headers.getHeaderString("X-tenantId");
        String systemId = headers.getHeaderString("X-systemId");

        if (tenantId != null && systemId != null) {
            logger.info("Adding custom claims: tenantId=" + tenantId + ", systemId=" + systemId);
            accessToken.getOtherClaims().put("tenantId", tenantId);
            accessToken.getOtherClaims().put("systemId", systemId);
        }

        return accessToken;
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "Context Token Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds tenantId and systemId claims to tokens if provided in request headers.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
