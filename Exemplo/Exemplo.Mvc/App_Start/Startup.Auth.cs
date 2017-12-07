using System;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Web.Mvc;
using Infra.CrossCutting.Identity.Configuracao;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Facebook;
using System.Threading.Tasks;
using Microsoft.Owin.Security.MicrosoftAccount;

namespace Mvc
{
    public  partial class Startup
    {
        public static IDataProtectionProvider DataProtectionProvider { get; set; }

        public void ConfigureAuth(IAppBuilder app)
        {

           
            app.CreatePerOwinContext(() => DependencyResolver.Current.GetService<ApplicationUserManager>());
           
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    
                    OnValidateIdentity = ApplicationCookieIdentityValidator.OnValidateIdentity(
                       validateInterval: TimeSpan.FromMinutes(0),
                       regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);
            
            var ms = new MicrosoftAccountAuthenticationOptions()
            {
              ClientId = "f5cc37f6-6226-40a6-8cde-243eec5b53cf",
              ClientSecret = "EsjKaTtccXn40txOJPqauFo",
                Provider = new MicrosoftAccountAuthenticationProvider()
                {
                    OnAuthenticated = context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("urn:microsoftaccount:access_token", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:microsoftaccount:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Microsoft"));
                        }

                        return Task.FromResult(0);
                    }
                }
            };

            //ms.Scope.Add("https://graph.microsoft.com/mail.read", "https://graph.microsoft.com/mail.send" }");


            ms.Scope.Add("https://graph.microsoft.com/mail.read");
            ms.Scope.Add("https://graph.microsoft.com/mail.send");
            ms.Scope.Add("https://graph.microsoft.com/calendar.read");



            var google = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "713668382610-29o2l6s48u5dnpkb09mlorb17m6b86a8.apps.googleusercontent.com",
                ClientSecret = "QgwkPBrZiDIfAIEDSy7723Vc"
            };
            
            google.Provider = new GoogleOAuth2AuthenticationProvider()
            {
                OnAuthenticated =  context =>
                {
                    context.Identity.AddClaim(new System.Security.Claims.Claim("GoogleAccessToken", context.AccessToken));
                    foreach (var claim in context.User)
                    {
                        var claimType = string.Format("urn:google:{0}", claim.Key);
                        string claimValue = claim.Value.ToString();
                        if (!context.Identity.HasClaim(claimType, claimValue))
                            context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Google"));
                    }

                    return Task.FromResult(0);
                }
            };


            var fao = new FacebookAuthenticationOptions
            {
                AppId = "1970826363204077",
                AppSecret = "fc1c5f2549259dc64cd8a01d756f5f73",
               UserInformationEndpoint = "https://graph.facebook.com/v2.4/me?fields=id,name,email,first_name,last_name"

           };

            fao.Scope.Add("email");
            fao.Scope.Add("publish_actions");
            fao.Scope.Add("public_profile");
            fao.Scope.Add("user_friends");



            fao.Provider = new FacebookAuthenticationProvider()
            {

                OnAuthenticated = (context) =>
                {
                    context.Identity.AddClaim(new System.Security.Claims.Claim("urn:facebook:access_token", context.AccessToken, "XmlSchemaString", "Facebook"));
                    foreach (var x in context.User)
                    {
                        var claimType = string.Format("urn:facebook:{0}", x.Key);
                        string claimValue = x.Value.ToString();
                        if (!context.Identity.HasClaim(claimType, claimValue))
                            context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Facebook"));

                    }
                    return Task.FromResult(0);
                }
            };

            
            
            fao.SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie;
            app.UseFacebookAuthentication(fao);
            app.UseGoogleAuthentication(google);
            app.UseMicrosoftAccountAuthentication(ms);
            
        }        
    }
}
