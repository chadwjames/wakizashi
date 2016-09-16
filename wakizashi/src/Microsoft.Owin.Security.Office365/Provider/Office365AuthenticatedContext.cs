using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Office365
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class Office365AuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="Office365AuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Office365 Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public Office365AuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            BusinessPhones =  new List<string>();
            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "displayName");
            UserName = TryGetValue(user, "userPrincipalName");
            Email = TryGetValue(user, "email");
            JobTitle = TryGetValue(user, "jobTitle");
            MobilePhone = TryGetValue(user, "mobilePhone");
            OfficeLocation = TryGetValue(user, "officeLocation");

        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Office365 access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Office365 access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Office365 user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's business phones
        /// </summary>
        public List<string> BusinessPhones { get; private set; }

        /// <summary>
        /// Get's the user's job title
        /// </summary>
        public string JobTitle { get; private set; }

        /// <summary>
        /// Get's the user's mobile phone.
        /// </summary>
        public string MobilePhone { get; private set; }

        /// <summary>
        /// Get's teh user's office location
        /// </summary>
        public string OfficeLocation { get; private set; }

        /// <summary>
        /// Gets the Office365 username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Office365 email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
