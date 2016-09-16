namespace Microsoft.Owin.Security.Office365
{
    internal static class Constants
    {
        public const string DefaultAuthenticationType = "Office365";
        internal const string AuthorizationEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
        internal const string TokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";   
        internal const string UserInformationEndpoint = "https://graph.microsoft.com/v1.0/me";
    }
}
