package system;

import com.mendix.core.actionmanagement.IActionRegistrator;

public class UserActionsRegistrar
{
  public void registerActions(IActionRegistrator registrator)
  {
    registrator.bundleComponentLoaded();
    registrator.registerUserAction(appcloudservices.actions.CreateUserWithUserProfile.class);
    registrator.registerUserAction(appcloudservices.actions.DecryptString.class);
    registrator.registerUserAction(appcloudservices.actions.EncryptString.class);
    registrator.registerUserAction(appcloudservices.actions.GenerateRandomPassword.class);
    registrator.registerUserAction(appcloudservices.actions.GetTokenEndpointURI.class);
    registrator.registerUserAction(appcloudservices.actions.InitializeUserMapper.class);
    registrator.registerUserAction(appcloudservices.actions.LogOutUser.class);
    registrator.registerUserAction(appcloudservices.actions.StartSignOnServlet.class);
    registrator.registerUserAction(appcloudservices.actions.UpdateUserWithUserProfile.class);
    registrator.registerUserAction(system.actions.VerifyPassword.class);
  }
}
