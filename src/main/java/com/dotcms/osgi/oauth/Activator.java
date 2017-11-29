package com.dotcms.osgi.oauth;

import com.dotcms.cms.login.LoginServiceAPI;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotcms.repackage.org.apache.commons.lang.StringUtils;
import com.dotcms.repackage.org.apache.logging.log4j.LogManager;
import com.dotcms.repackage.org.apache.logging.log4j.core.LoggerContext;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.Condition;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.NormalRule;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.Rule;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.filters.CMSFilter;
import com.dotmarketing.filters.DotUrlRewriteFilter;
import com.dotmarketing.filters.LoginRequiredFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.liferay.portal.util.WebKeys;
import org.apache.felix.http.api.ExtHttpService;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

import static com.dotcms.osgi.oauth.OAuth2Servlet.CODE_PARAM_KEY;
import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

public class Activator extends GenericBundleActivator {

    private static final String NATIVE = "native";
    private List<Rule> rules = new ArrayList<Rule>();
    private ExtHttpService httpService;
    private OAuth2Servlet servlet;
    private static final String OAUTH_URL = "/oauth2";
    private LoggerContext pluginLoggerContext;
    private BackEndLoginRequiredOAuthInterceptor backEndLoginInterceptor;
    private LoginServiceAPI loginServiceAPI;

    @SuppressWarnings("unchecked")
    public void start(BundleContext context) throws Exception {

        this.loginServiceAPI = APILocator.getLoginServiceAPI();
        //Initializing log4j...
        final LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();

        //Initialing the log4j context of this plugin based on the dotCMS logger context
        this.pluginLoggerContext = (LoggerContext) LogManager.getContext(this.getClass().getClassLoader(),
                false,
                dotcmsLoggerContext,
                dotcmsLoggerContext.getConfigLocation());

        Logger.info(this.getClass(), "Starting OSGi OAuth Filter");

        // Initializing services...
        this.initializeServices(context);

        final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR","").toLowerCase();
        final boolean frontEnd = useFor.contains ("frontend");
        final boolean backEnd = useFor.contains ("backend");

        this.registerViewToolService(context, new OAuthToolInfo());

        ServiceReference<ExtHttpService> sRef = (ServiceReference<ExtHttpService>) context.getServiceReference(ExtHttpService.class.getName());
        if ( sRef != null ) {

            //Publish bundle services
            this.publishBundleServices( context );
            this.httpService = (ExtHttpService) context.getService( sRef );

            try {
                //Registering a simple test servlet
                servlet = new OAuth2Servlet();
                httpService.registerServlet( OAUTH_URL, servlet, null, null );

            } catch ( Exception e ) {
                e.printStackTrace();
            }

            CMSFilter.addExclude( "/app" + OAUTH_URL );
        }

        this.addRules(frontEnd, backEnd);

        Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");

    }

    private void addRules(final boolean frontEnd, final boolean backEnd) throws Exception {
        NormalRule rule = null;

        //Create Conditions for this rule
        final Condition condition1 = new Condition();
        condition1.setName(NATIVE);
        condition1.setType("parameter");
        condition1.setOperator("notequal");
        condition1.setValue( "^.+$" );

        //Create another Condition for this rule
        final Condition condition2 = new Condition();
        condition2.setName( "my_account_r_m" );
        condition2.setType("parameter");
        condition2.setOperator("notequal");
        condition2.setValue( "^.+$" );

        this.rules = new ArrayList<Rule>();

        if(frontEnd) {

            this.addRule("oauth-rule" + this.rules.size(), "^/dotCMS/login.*$",
                    "/app" + OAUTH_URL, condition1, condition2);
        }

        if(backEnd) {

            this.backEndLoginInterceptor = new BackEndLoginRequiredOAuthInterceptor();
            FilterWebInterceptorProvider.getInstance(Config.CONTEXT)
                    .getDelegate(LoginRequiredFilter.class).addFirst(this.backEndLoginInterceptor);
        }
    }

    private void addRule (final String name, final String from,
                          final String to, final Condition condition1,
                          final Condition condition2) throws Exception {

        final NormalRule rule = new NormalRule();

        Logger.info(this.getClass(), MessageFormat.format(
                "Adding rule Name= {0}, From= {1}, To = {2}", name, from, to));
        rule.setName(name);
        rule.setFrom(from);
        rule.setTo  (to);
        rule.setToType("redirect");
        rule.addCondition(condition1);
        rule.addCondition(condition2);
        this.addRewriteRule(rule);
        this.rules.add(rule);
    } // addRule.

    public void stop(BundleContext context) throws Exception {
        //Unregister the servlet
        if ( httpService != null && servlet != null ) {
            httpService.unregisterServlet( servlet );
        }

        Logger.info(this.getClass(), "Removing OSGi OAuth Servlet");

        for(Rule rule : rules){

            DotUrlRewriteFilter.getUrlRewriteFilter().removeRule(rule);
        }

        if (null != this.backEndLoginInterceptor) {
            FilterWebInterceptorProvider.getInstance(Config.CONTEXT)
                    .getDelegate(LoginRequiredFilter.class).remove(this.backEndLoginInterceptor.getName(), true);
        }

        unregisterViewToolServices();

        Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");

        //Shutting down log4j in order to avoid memory leaks
        Log4jUtil.shutdown(pluginLoggerContext);

        CMSFilter.removeExclude( "/app" + OAUTH_URL  );

        //Unpublish bundle services
        unregisterServices( context );

    }

    /**
     * This interceptor is used for handle the OAuth login check on DotCMS BE.
     * @author jsanca
     */
    public class BackEndLoginRequiredOAuthInterceptor implements WebInterceptor {


        public static final String NAME = "BackEndLoginRequiredOAuthInterceptor4_1";

        @Override
        public String getName() {
            return NAME;
        }

        /**
         * This login required will be used for the BE, when the user is on BE, is not logged in and
         * the by pass native=true is not in the query string will redirect to the OAUTH Servlet in order to do
         * the authentication with OAUTH
         */
        @Override
        public Result intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

            final HttpSession session = request.getSession(false);
            final boolean isAdmin = request.getRequestURI().startsWith("/dotAdmin");
            Result result  = Result.NEXT;

            final boolean isAuthorizedResponse = request.getRequestURI().startsWith("/app/oauthCallback");

            if (isAuthorizedResponse) {
                Logger.warn(this.getClass(),"Processing Authorization Request:" + request.
                        getParameter(CODE_PARAM_KEY));
                response.sendRedirect("/app" + OAUTH_URL + "?" + CODE_PARAM_KEY + "=" +
                        request.getParameter(CODE_PARAM_KEY));
                result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
            }

            // if we are not logged in, is a admin request and not native by pass, go to login page
            if ( isAdmin && !Activator.this.loginServiceAPI.isLoggedIn(request) &&
                    !Boolean.TRUE.toString().equalsIgnoreCase(request.getParameter(NATIVE))) {

                Logger.warn(this.getClass(),
                        "Doing Login Check for RequestURI: " +
                                request.getRequestURI() + "?" + request.getQueryString());

                response.sendRedirect("/app" + OAUTH_URL + "?referrer=/dotAdmin");
                result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
            }

            return result; // if it is log in, continue!
        } // intercept.
    } // BackEndLoginRequiredOAuthInterceptor.
}