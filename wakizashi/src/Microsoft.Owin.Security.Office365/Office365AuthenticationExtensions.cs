using System;
using Owin;

namespace Microsoft.Owin.Security.Office365
{
    /// <summary>
    /// Extension methods for using <see cref="Office365AuthenticationMiddleware"/>
    /// </summary>
    public static class Office365AuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Office365
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOffice365Authentication(this IAppBuilder app, Office365AuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            app.Use(typeof(Office365AuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Office365
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by Office365</param>
        /// <param name="appSecret">The appSecret assigned by Office365</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOffice365Authentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseOffice365Authentication(
                app,
                new Office365AuthenticationOptions
                {
                    ClientId = appId,
                    ClientSecret = appSecret,
                });
        }
    }
}
