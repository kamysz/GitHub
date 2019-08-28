package appcloudservices.implementation.handlers;

import appcloudservices.proxies.UserProfile;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IUser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;


interface ILoginHandler {

    void onCompleteLogin(IContext context, UserProfile openId, OIDCTokenResponse oidcTokenResponse, String continuation, IMxRuntimeRequest req, IMxRuntimeResponse resp) throws Exception;

    void onAlreadyHasSession(IContext context, IUser user, String continuation, IMxRuntimeRequest req, IMxRuntimeResponse resp) throws Exception;

}
