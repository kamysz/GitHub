package appcloudservices.implementation;

import appcloudservices.implementation.handlers.OpenIDHandler;
import appcloudservices.implementation.utils.MendixUtils;
import appcloudservices.implementation.utils.OpenIDUtils;
import appcloudservices.proxies.Token;
import appcloudservices.proxies.TokenType;
import appcloudservices.proxies.UserProfile;
import appcloudservices.proxies.microflows.Microflows;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import com.mendix.systemwideinterfaces.core.ISession;
import com.mendix.systemwideinterfaces.core.IUser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import system.proxies.User;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static appcloudservices.proxies.constants.Constants.getLogNode;
import static appcloudservices.proxies.microflows.Microflows.encrypt;

public class SessionInitializer {

    public static final String XASID_COOKIE = "XASID";
    private static final String ORIGIN_COOKIE = "originURI";
    private static final ILogNode LOG = Core.getLogger(getLogNode());
    private static final String XAS_SESSION_ID = Core.getConfiguration().getSessionIdCookieName();
    private static final String USER_ENTITY = UserMapper.getInstance().getUserEntityName();
    private static final String USER_ENTITY_NAME = "Name";
    private static final String DEFAULT_MENDIX_USERNAME_ATTRIBUTE = "Name";


    /**
     * Given a username, starts a new session for the user and redirects back to index.html.
     * If no matching account is found for the user, a new account will be created automatically.
     *
     * @param resp
     * @param req
     * @param user
     * @return
     * @throws CoreException
     * @throws IOException
     * @throws NoSuchMethodException
     * @throws SecurityException
     */
    static public void createSessionForUser(IContext context, IMxRuntimeResponse resp,
                                            IMxRuntimeRequest req, IUser user, OIDCTokenResponse oidcTokenResponse) throws Exception {

        LOG.info("User " + user.getName() + " authenticated. Starting session..");

        final String sessionid = req.getCookie(XAS_SESSION_ID);

        final ISession session = Core.initializeSession(user, sessionid);

        // Used to enable Single Sign Off request (from remote sso *server*); must only sign off user in a particular User Agent / Browser
        final String ua = req.getHeader("User-Agent");
        session.setUserAgent(ua);

        if (oidcTokenResponse != null && oidcTokenResponse.getTokens() != null) {

            if (oidcTokenResponse.getTokens().getAccessToken() != null) {
                createToken(context, session, user, TokenType.ACCESS_TOKEN,
                        oidcTokenResponse.getTokens().getAccessToken().getValue());
            }

            if (oidcTokenResponse.getTokens().getRefreshToken() != null) {
                createToken(context, session, user, TokenType.REFRESH_TOKEN,
                        oidcTokenResponse.getTokens().getRefreshToken().getValue());
            }

            if (oidcTokenResponse.getOIDCTokens().getIDToken() != null) {
                createToken(context, session, user, TokenType.ID_TOKEN,
                        oidcTokenResponse.getOIDCTokens().getIDToken().getParsedString());
            }

        } else {

            // the only way to get here is via DefaultLoginHandler.onAlreadyHasSession(),
            // so we can safely assume that the current session already has tokens

            // so we retrieve all tokens from the old session, ...
            final List<Token> tokens = retrieveTokensForSession(context, sessionid);

            // and migrate them to the newly created one
            for (Token token : tokens) {
                token.setSessionId(session.getId().toString());
                token.commit();
            }

        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Created session, fingerprint: " + OpenIDUtils.getFingerPrint(session));
        }

        writeSessionCookies(resp, session);

    }

    private static void writeSessionCookies(IMxRuntimeResponse resp,
                                            ISession session) {
        resp.addCookie(XAS_SESSION_ID, session.getId().toString(), "/", "", -1, true);
        resp.addCookie(XASID_COOKIE, "0." + Core.getXASId(), "/", "", -1, true);
        resp.addCookie(ORIGIN_COOKIE, "/" + OpenIDHandler.OPENID_CLIENTSERVLET_LOCATION + OpenIDHandler.LOGIN, "/", "", -1, false);
    }

    public static void redirectToIndex(IMxRuntimeResponse resp, String continuation) {
        resp.setStatus(IMxRuntimeResponse.SEE_OTHER);

        //no continuation provided, use index
        if (continuation == null)
            resp.addHeader("location", OpenIDHandler.INDEX_PAGE);
        else {
            if (continuation.trim().startsWith("javascript:")) {
                throw new IllegalArgumentException("Javascript injection detected!");
            } else if (!continuation.startsWith("http://") && !continuation.startsWith("https://")) {
                resp.addHeader("location", OpenIDUtils.APPLICATION_ROOT_URL + continuation);
            } else {
                resp.addHeader("location", continuation);
            }
        }
    }

    /**
     * Finds a user account matching the given username. If not found the new account callback triggered.
     *
     * @param userProfile
     * @return Newly created user or null.
     * @throws Throwable
     * @throws CoreException
     */
    public static IUser findOrCreateUser(UserProfile userProfile) throws Throwable {
        IContext c = Core.createSystemContext();
        c.startTransaction();
        String openID = userProfile.getOpenId();
        try {

            IUser user = findUser(c, openID);

            //Existing user
            if (user != null) {
                try {
                    Microflows.invokeOnNonFirstLoginAppCloudUser(c, userProfile);
                } catch (Exception e) {
                    LOG.warn("Failed to update user roles for '" + openID + "', permissions for this user might be outdated", e);
                }
            }

            //New user
            else {
                String basemsg = "User '" + openID + "' does not exist in database. Triggering OnFirstLogin action... ";
                LOG.info(basemsg);

                //Expect user input here.
                // Create new user:
                Microflows.invokeOnFirstLoginAppCloudUser(c, userProfile);

                IUser newUser = findUser(c, openID);
                if (newUser != null) {
                    LOG.info(basemsg + "Account created.");
                    user = newUser;
                } else {
                    LOG.info(basemsg + "No user was created. Rejecting the login request.");
                }
            }

            c.endTransaction();
            return user;
        } catch (Throwable e) {
            LOG.warn("Find or create user for openID '" + openID + "' caught exception. Triggering rollback.");
            c.rollbackTransAction();
            throw e;
        }
    }

    public static void notifyAlreadyHasSession(IUser user) {
        IContext c = Core.createSystemContext();
        c.startTransaction();
        String openID = user.getName();
        try {

            Microflows.invokeOnAlreadyHasSessionAppCloudUser(c, User.initialize(c, user.getMendixObject()));

            c.endTransaction();
        } catch (Throwable e) {
            LOG.warn("Find or create user for openID '" + openID + "' caught exception. Triggering rollback.");
            c.rollbackTransAction();
            throw e;
        }
    }

    private static IUser findUser(IContext c, String openID) throws CoreException {
        List<IMendixObject> userList = Core.retrieveXPathQuery(c, String.format("//%s[%s='%s']", USER_ENTITY, USER_ENTITY_NAME, openID));

        if (userList.size() > 0) {
            IMendixObject userObject = userList.get(0);
            String username = userObject.getValue(c, DEFAULT_MENDIX_USERNAME_ATTRIBUTE);
            if (LOG.isTraceEnabled())
                LOG.trace("Getting System.User using username: '" + username + "'");

            return Core.getUser(c, username);
        } else {
            return null;
        }
    }

    private static void createToken(IContext context, ISession session, IUser user, TokenType tokenType, String value) throws CoreException {
        final Token newToken = new Token(context);
        newToken.setTokenType(tokenType);
        newToken.setValue(encrypt(context, value));
        newToken.setSessionId(session.getId().toString());
        newToken.setToken_User(User.initialize(context, user.getMendixObject()));
        newToken.commit();
    }

    private static List<Token> retrieveTokensForSession(IContext context, String sessionId) {
        return MendixUtils.retrieveFromDatabase(context, Token.class,
                "//%s[%s = $sessionId]",
                new HashMap<String, Object>() {{
                    put("sessionId", sessionId);
                }},
                Token.entityName,
                Token.MemberNames.SessionId.toString()
        );
    }

}
