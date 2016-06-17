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
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.User;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;
import twitter4j.conf.ConfigurationBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Twitter
 */
public class TwitterAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(TwitterAuthenticator.class);

    public boolean canHandle(HttpServletRequest request) {
        return (request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_TOKEN) != null
                && request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_VERIFIER) != null);
    }

    public String getContextIdentifier(HttpServletRequest request) {
        if (request.getSession().getAttribute(TwitterAuthenticatorConstants.TWITTER_CONTEXT_IDENTIFIER) == null) {
            request.getSession().setAttribute(TwitterAuthenticatorConstants.TWITTER_CONTEXT_IDENTIFIER,
                    request.getParameter(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY));
            return (String) request.getSession().getAttribute(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY);
        } else {
            return (String) request.getSession().getAttribute(TwitterAuthenticatorConstants.TWITTER_CONTEXT_IDENTIFIER);
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
        configurationBuilder.setIncludeEmailEnabled(true);
        Twitter twitter = new TwitterFactory(configurationBuilder.build()).getInstance();
        twitter.setOAuthConsumer(apiKey, apiSecret);
        try {
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String callbackURL = getCallbackUrl(authenticatorProperties);
            RequestToken requestToken = twitter.getOAuthRequestToken(callbackURL.toString());
            String subStr = queryParams.substring(queryParams
                    .indexOf(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY + "="));
            String sessionDK = subStr.substring(subStr.indexOf(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY
                    + "="), subStr.indexOf("&")).replace((TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY + "=")
                    , "");
            request.getSession().setAttribute(TwitterAuthenticatorConstants.TWITTER_SESSION_DATA_KEY, sessionDK);
            request.getSession().setAttribute(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN, requestToken);
            request.getSession().setAttribute(TwitterAuthenticatorConstants.AUTHENTICATOR_NAME.toLowerCase(), twitter);
            response.sendRedirect(requestToken.getAuthenticationURL());
        } catch (TwitterException e) {
            log.error("Exception while sending to the Twitter login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (IOException e) {
            log.error("Exception while sending to the Twitter login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Process the response of the Twitter
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        Twitter twitter = (Twitter) request.getSession().getAttribute(TwitterAuthenticatorConstants.AUTHENTICATOR_NAME
                .toLowerCase());
        RequestToken requestToken =
                (RequestToken) request.getSession().getAttribute(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN);
        String verifier = request.getParameter(TwitterAuthenticatorConstants.TWITTER_OAUTH_VERIFIER);
        try {
            AccessToken token = twitter.getOAuthAccessToken(requestToken, verifier);
            request.getSession().removeAttribute(TwitterAuthenticatorConstants.TWITTER_REQUEST_TOKEN);
            User user = twitter.verifyCredentials();
            if (token != null) {
                buildClaims(user, context);
            }
        } catch (TwitterException e) {
            log.error("Exception while obtaining OAuth token form Twitter", e);
            throw new AuthenticationFailedException("Exception while obtaining OAuth token form Twitter", e);
        }
    }

    public void buildClaims(User user, AuthenticationContext context) {
        AuthenticatedUser authenticatedUserObj;
        authenticatedUserObj = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(user.getId() + "");
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(user.getId() + "");

        Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
        claims.put(ClaimMapping.build(TwitterAuthenticatorConstants.TWITTER_CLAIM_NAME,
                TwitterAuthenticatorConstants.TWITTER_CLAIM_NAME, (String) null, false), user.getName());
        claims.put(ClaimMapping.build(TwitterAuthenticatorConstants.TWITTER_CLAIM_EMAIL,
                TwitterAuthenticatorConstants.TWITTER_CLAIM_EMAIL, (String) null, false), user.getEmail());
        claims.put(ClaimMapping.build(TwitterAuthenticatorConstants.TWITTER_CLAIM_LOCATION,
                TwitterAuthenticatorConstants.TWITTER_CLAIM_LOCATION, (String) null, false), user.getLocation());
        authenticatedUserObj.setUserAttributes(claims);
        context.setSubject(authenticatedUserObj);
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return TwitterAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return TwitterAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the CallBackURL
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {
        if (StringUtils.isNotEmpty((String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return (String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return TwitterAuthenticatorConstants.TWITTER_CALLBACK_URL;
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

