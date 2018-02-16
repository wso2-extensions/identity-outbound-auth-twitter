/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.twitter;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import twitter4j.JSONException;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.TwitterObjectFactory;
import twitter4j.User;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;
import twitter4j.conf.ConfigurationBuilder;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TwitterAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4844100162196896194L;
    private static final Log log = LogFactory.getLog(TwitterAuthenticator.class);

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(TwitterAuthenticatorConstants.STATE_PARAM);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return ((isOauthParamExists(request) && TwitterAuthenticatorConstants.TWITTER_LOGIN_TYPE.equals
                (request.getParameter(TwitterAuthenticatorConstants.LOGIN_TYPE_PARAM))) || isErrorParamExists(request));
    }

    /**
     * Check access denied error param exist in request.
     *
     * @param request httpServletRequest
     * @return true or false
     */
    private boolean isErrorParamExists(HttpServletRequest request) {
        return request.getParameter(TwitterAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null;
    }

    /**
     * Check whether oauth_token and oauth_verifier param exist in request.
     *
     * @param request httpServletRequest
     * @return true or false
     */
    private boolean isOauthParamExists(HttpServletRequest request) {
        return (request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_TOKEN) != null
                && request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_VERIFIER) != null);
    }

    /**
     * Handle error response when click on cancel without providing credentials.
     *
     * @param request httpServletRequest
     * @throws InvalidCredentialsException
     */
    private void handleErrorResponse(HttpServletRequest request) throws InvalidCredentialsException {
        if (isErrorParamExists(request)) {
            String error = request.getParameter(TwitterAuthenticatorConstants.OAUTH2_PARAM_ERROR);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via Twitter when click on cancel without providing credentials" +
                        error);
            }
            throw new InvalidCredentialsException(error);
        }
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        ConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String apiKey = authenticatorProperties.get(TwitterAuthenticatorConstants.TWITTER_API_KEY);
        String apiSecret = authenticatorProperties.get(TwitterAuthenticatorConstants.TWITTER_API_SECRET);
        configurationBuilder.setDebugEnabled(true)
                .setIncludeEmailEnabled(true)
                .setJSONStoreEnabled(true);
        Twitter twitter = new TwitterFactory(configurationBuilder.build()).getInstance();
        twitter.setOAuthConsumer(apiKey, apiSecret);
        try {
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String callbackURL = getCallbackUrl(authenticatorProperties);

            String callbackWithParams = new URIBuilder(callbackURL)
                    .addParameter(TwitterAuthenticatorConstants.STATE_PARAM, context.getContextIdentifier())
                    .addParameter(TwitterAuthenticatorConstants.LOGIN_TYPE_PARAM, TwitterAuthenticatorConstants
                            .TWITTER_LOGIN_TYPE)
                    .build().toString();
            RequestToken requestToken = twitter.getOAuthRequestToken(URLEncoder.encode(callbackWithParams, "UTF-8"));

            String subStr = queryParams.substring(queryParams
                    .indexOf(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY + "="));
            String sessionDK = subStr.substring(subStr.indexOf(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY
                    + "="), subStr.indexOf("&")).replace((TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY + "=")
                    , "");
            context.setProperty(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY, sessionDK);
            context.setProperty(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN, requestToken);
            context.setProperty(TwitterAuthenticatorConstants.AUTHENTICATOR_NAME.toLowerCase(), twitter);
            response.sendRedirect(requestToken.getAuthenticationURL());
        } catch (TwitterException e) {
            log.error("Exception while sending to the Twitter login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (IOException e) {
            log.error("Exception while sending to the Twitter login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new AuthenticationFailedException("Invalid Callback URL provided.", e);
        }
    }

    /**
     * Get the CallBackURL
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty(authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
    }

    @Override
    public String getClaimDialectURI() {
        String claimDialectUri = null;
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            Map<String, String> parameters = authConfig.getParameterMap();
            if (parameters != null && parameters.containsKey(TwitterAuthenticatorConstants.
                    CLAIM_DIALECT_URI_PARAMETER)) {
                claimDialectUri = parameters.get(TwitterAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found no Parameter map for connector " + getName());
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + getName() + " is using the claim dialect uri " + claimDialectUri);
        }
        return claimDialectUri;
    }

    /**
     * Process the response of the Twitter
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        handleErrorResponse(request);
        Twitter twitter = (Twitter) context.getProperty(TwitterAuthenticatorConstants.AUTHENTICATOR_NAME.toLowerCase());
        RequestToken requestToken = (RequestToken) context.getProperties().get(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN);
        String verifier = request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_VERIFIER);
        try {
            AccessToken token = twitter.getOAuthAccessToken(requestToken, verifier);
            request.getSession().removeAttribute(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN);
            User user = twitter.verifyCredentials();
            String json = TwitterObjectFactory.getRawJSON(user);
            if (token != null) {
                try {
                    buildClaims(context, json);
                } catch (JSONException e) {
                    log.error("Error while parsing the json");
                } catch (ApplicationAuthenticatorException e) {
                    log.error("Error while building the claim");
                }
            }
        } catch (TwitterException e) {
            log.error("Exception while obtaining OAuth token form Twitter", e);
            throw new AuthenticationFailedException("Exception while obtaining OAuth token form Twitter", e);
        }
    }

    public void buildClaims(AuthenticationContext context, String jsonObject)
            throws ApplicationAuthenticatorException, JSONException {
        Map<String, Object> userClaims;
        userClaims = JSONUtils.parseJSON(jsonObject);
        if (userClaims != null) {
            Map<ClaimMapping, String> claims = new HashMap<>();
            String claimDialectUri = getClaimDialectURI();
            if (claimDialectUri == null) {
                claimDialectUri = "";
            } else {
                claimDialectUri += "/";
            }
            for (Map.Entry<String, Object> entry : userClaims.entrySet()) {
                String claimUri = claimDialectUri + entry.getKey();
                claims.put(ClaimMapping.build(claimUri, claimUri, null, false),
                        entry.getValue().toString());
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Adding claim mapping : " + claimUri + " <> " + claimUri + " : " + entry.getValue());
                }
            }
            if (StringUtils.isBlank(context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig().setUserClaimURI
                        (TwitterAuthenticatorConstants.CLAIM_ID);
            }
            String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                    context.getExternalIdP().getIdentityProvider(), claims);
            if (subjectFromClaims != null && !subjectFromClaims.isEmpty()) {
                AuthenticatedUser authenticatedUser =
                        AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, userClaims);
            }
            context.getSubject().setUserAttributes(claims);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    private void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {
        String authenticatedUserId = String.valueOf(jsonObject.get(TwitterAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));
        if (log.isDebugEnabled()) {
            log.debug("The subject claim that you have selected is null. The default subject claim " +
                    authenticatedUserId + " has been set");
        }
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    @Override
    public String getFriendlyName() {
        return TwitterAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return TwitterAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property apiKey = new Property();
        apiKey.setName(TwitterAuthenticatorConstants.TWITTER_API_KEY);
        apiKey.setDisplayName("API Key");
        apiKey.setRequired(true);
        apiKey.setDescription("Enter the API Key of the twitter account");
        apiKey.setDisplayOrder(0);
        configProperties.add(apiKey);

        Property apiSecret = new Property();
        apiSecret.setName(TwitterAuthenticatorConstants.TWITTER_API_SECRET);
        apiSecret.setDisplayName("API Secret");
        apiSecret.setRequired(true);
        apiSecret.setConfidential(true);
        apiSecret.setDescription("Enter the API Secret");
        apiSecret.setDisplayOrder(1);
        configProperties.add(apiSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter the Callback URL");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);
        return configProperties;
    }
}
