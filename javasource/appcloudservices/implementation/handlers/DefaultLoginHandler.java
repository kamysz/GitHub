package appcloudservices.implementation.handlers;

import appcloudservices.implementation.SessionInitializer;
import appcloudservices.implementation.handlers.OpenIDHandler.ResponseType;
import appcloudservices.proxies.UserProfile;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IUser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import java.io.IOException;


public class DefaultLoginHandler implements ILoginHandler {

    public void onCompleteLogin(IContext context, UserProfile userProfile, OIDCTokenResponse oidcTokenResponse, String continuation, IMxRuntimeRequest req, IMxRuntimeResponse resp)
            throws IllegalStateException, IOException {
        IUser user;
        try {
            user = SessionInitializer.findOrCreateUser(userProfile);
        } catch (Throwable e) {
            OpenIDHandler.error(resp, ResponseType.INTERNAL_SERVER_ERROR, "We failed to register your account in this app. Please try again later or contact the administrator of this app.", e);
            return;
        }

        if (user == null) {
            OpenIDHandler.error(resp, ResponseType.UNAUTHORIZED, "Your account has not been authorized to use this application. ", null);
        } else if (user.getUserRoleNames().size() == 0) {
            OpenIDHandler.error(resp, ResponseType.UNAUTHORIZED, "Your account has not been authorized to use this application. No permissions for this app have been assigned to your account. ", null);
        } else {
            try {
                SessionInitializer.createSessionForUser(context, resp, req, user, oidcTokenResponse);
                SessionInitializer.redirectToIndex(resp, continuation);
            } catch (Exception e) {
                OpenIDHandler.error(resp, ResponseType.INTERNAL_SERVER_ERROR, "Failed to initialize session", e);
            }
        }
    }

    @Override
    public void onAlreadyHasSession(IContext context, IUser user, String continuation, IMxRuntimeRequest req, IMxRuntimeResponse resp) throws Exception {
        if (user == null) {
            OpenIDHandler.error(resp, ResponseType.UNAUTHORIZED, "Your account has not been authorized to use this application. ", null);
        } else if (user.getUserRoleNames().size() == 0) {
            OpenIDHandler.error(resp, ResponseType.UNAUTHORIZED, "Your account has not been authorized to use this application. No permissions for this app have been assigned to your account. ", null);
        } else {
            try {
                SessionInitializer.notifyAlreadyHasSession(user);
                SessionInitializer.createSessionForUser(context, resp, req, user, null);
                SessionInitializer.redirectToIndex(resp, continuation);
            } catch (Exception e) {
                OpenIDHandler.error(resp, ResponseType.INTERNAL_SERVER_ERROR, "Failed to initialize session", e);
            }
        }
    }

    @SuppressWarnings("unused")
    public void onCompleteAnonymousLogin(String continuation, IMxRuntimeRequest req, IMxRuntimeResponse resp)
            throws IllegalStateException, IOException {
        try {
            /* Setting up guest sessions is not the responsibility of this module, but otherwise:
             if (Core.getConfiguration().getEnableGuestLogin()) {
             ISession session = Core.initializeGuestSession();
             SessionInitializer.writeSessionCookies(resp, session);
             }
             */
            SessionInitializer.redirectToIndex(resp, continuation);
        } catch (Exception e) {
            OpenIDHandler.error(resp, ResponseType.INTERNAL_SERVER_ERROR, "Failed to initialize session", e);
        }
    }

}
