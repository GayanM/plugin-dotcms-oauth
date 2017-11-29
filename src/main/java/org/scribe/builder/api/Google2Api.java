package org.scribe.builder.api;
 
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
 
/**
 * Google OAuth2.0 
 * Released under the same license as scribe (MIT License)
 * @author yincrash
 * 
 */
public class Google2Api extends DefaultApi20 {
 
    private static final String AUTHORIZE_URL_PARAMS = "?response_type=code&client_id=%s&redirect_uri=%s";
    private static final String SCOPED_AUTHORIZE_URL_PARAMS = AUTHORIZE_URL_PARAMS + "&scope=%s";
    private static final String PROVIDER_CLASS = "Google2Api";
 
    @Override
    public String getAccessTokenEndpoint() {
        return getProperty(PROVIDER_CLASS + "_TOKEN_ENDPOINT");
    }
    
    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {
            
            @Override
            public Token extract(String response) {
                Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");
 
                Matcher matcher = Pattern.compile("\"access_token\":\"([^&\"]+)\"").matcher(response);
                if (matcher.find())
                {
                  String token = OAuthEncoder.decode(matcher.group(1));
                  return new Token(token, "", response);
                } 
                else
                {
                  throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
                }
            }
        };
    }
 
    @Override
    public String getAuthorizationUrl(OAuthConfig config) {

        String authorizedEndpoint = getProperty(PROVIDER_CLASS + "_AUTHORIZE_ENDPOINT");
        // Append scope if present
        if (config.hasScope()) {
            return authorizedEndpoint + String.format(SCOPED_AUTHORIZE_URL_PARAMS, config.getApiKey(),
                    OAuthEncoder.encode(config.getCallback()),
                    OAuthEncoder.encode(config.getScope()));
        } else {
            return authorizedEndpoint + String.format(AUTHORIZE_URL_PARAMS, config.getApiKey(),
                    OAuthEncoder.encode(config.getCallback()));
        }
    }
    
    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }
    
    @Override
    public OAuthService createService(OAuthConfig config) {
        return new GoogleOAuth2Service(this, config);
    }
    
    private class GoogleOAuth2Service extends OAuth20ServiceImpl {
 
        private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
        private static final String GRANT_TYPE = "grant_type";
        private DefaultApi20 api;
        private OAuthConfig config;
 
        public GoogleOAuth2Service(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }
        
        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {
            OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
            switch (api.getAccessTokenVerb()) {
            case POST:
                request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
                request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
                request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
                request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
                request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
                break;
            case GET:
            default:
                request.addQuerystringParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
                request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
                request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
                request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
                if(config.hasScope()) request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());
            }
            Response response = request.send();
            return api.getAccessTokenExtractor().extract(response.getBody());
        }
    }
 
}