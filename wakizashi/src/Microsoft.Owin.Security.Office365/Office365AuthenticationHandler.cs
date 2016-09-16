using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Office365
{
    internal class Office365AuthenticationHandler : AuthenticationHandler<Office365AuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public Office365AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;

                var values = query.GetValues("error");
                if (values != null && values.Count >= 1)
                {
                    _logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
                }

                values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                if (code == null)
                {
                    // Null if the remote server returns an error.
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                
                //get the scope
                var scope = string.Join(" ", Options.Scope);

                var tokenRequest = "grant_type=authorization_code" +
                    "&code=" + Uri.EscapeDataString(code) +
                    "&scope" + Uri.EscapeDataString(scope) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret);

                var content = new StringContent(tokenRequest);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "iDeal");

                var tokenResponse =
                    await
                        _httpClient.PostAsync(Options.TokenEndpoint, content, Request.CallCancelled);

                tokenResponse.EnsureSuccessStatusCode();
                var data = await tokenResponse.Content.ReadAsStringAsync();

                var jReponseData = JObject.Parse(data);

                var accessToken = jReponseData["access_token"]?.ToString();

                var expires = jReponseData["expires_in"]?.ToString();

                var graphAddress = Options.UserInformationEndpoint;

                var refreshToken = jReponseData["refresh_token"]?.ToString();

                //add custome hearder to graph request
                _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + accessToken);

                var graphResponse = await _httpClient.GetAsync(graphAddress, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();

                data = await graphResponse.Content.ReadAsStringAsync();
                var user = JObject.Parse(data);

                var context = new Office365AuthenticatedContext(Context, user, accessToken, expires)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.Id))                
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));                

                if (!string.IsNullOrEmpty(context.UserName))                
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));

                if (!string.IsNullOrEmpty(context.Email))                
                    // Many Office365 accounts do not set the email field.  Fall back to the UserName field instead.
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString,
                        Options.AuthenticationType));                
                else                
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.UserName, XmlSchemaString,
                        Options.AuthenticationType));
                
                if (!string.IsNullOrEmpty(context.Name))                
                    context.Identity.AddClaim(new Claim("urn:Office365:name", context.Name, XmlSchemaString, Options.AuthenticationType));

                if(!string.IsNullOrWhiteSpace(refreshToken))
                    context.Identity.AddClaim(new Claim("Office365RefreshToken", refreshToken));
                               
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                var currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                var redirectUri =
                    baseUri +
                    Options.CallbackPath;

                var properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // space separated
                var scope = string.Join(" ", Options.Scope);

                var state = Options.StateDataFormat.Protect(properties);

                var authorizationEndpoint =
                    Options.AuthorizationEndpoint +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                var redirectContext = new Office365ApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new Office365ReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

    }
}
