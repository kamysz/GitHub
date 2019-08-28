package appcloudservices.implementation.oidp;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import java.net.URI;

public class IdentityProviderMetaData {

    private final ClientID clientId;

    private final Secret clientSecret;

    private final OIDCProviderMetadata providerMetadata;

    private final IDTokenValidator idTokenValidator;

    private final URI redirectUri;

    private final ResponseType responseType;

    public IdentityProviderMetaData(ClientID clientId, String clientSecret,
                                    OIDCProviderMetadata providerMetadata, IDTokenValidator idTokenValidator, URI redirectUri, ResponseType responseType) {
        this.clientId = clientId;
        this.clientSecret = new Secret(clientSecret);
        this.providerMetadata = providerMetadata;
        this.idTokenValidator = idTokenValidator;
        this.redirectUri = redirectUri;
        this.responseType = responseType;
    }

    public ClientID getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public OIDCProviderMetadata getProviderMetadata() {
        return providerMetadata;
    }

    public IDTokenValidator getIdTokenValidator() {
        return idTokenValidator;
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }


}
