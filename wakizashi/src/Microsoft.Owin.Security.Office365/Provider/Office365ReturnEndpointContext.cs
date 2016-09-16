using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Office365
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class Office365ReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public Office365ReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
