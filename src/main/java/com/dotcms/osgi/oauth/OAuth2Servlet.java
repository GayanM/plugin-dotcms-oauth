/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have
 * chosen to have their login information remembered.
 * Creates a valid WebSession object and
 * passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth;

import com.dotcms.cms.login.LoginServiceAPI;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotcms.repackage.org.apache.commons.lang.StringUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.dotmarketing.viewtools.JSONTool;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.*;
import org.scribe.oauth.OAuthService;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

/**
 * Encapsulates the login to handle the OAUTH callback on dotCMS and also the third-party authorization (Facebook or Google).
 * @author Will, Jsanca
 */
public class OAuth2Servlet extends HttpServlet {

	private static final long serialVersionUID = -7036009330382977246L;
	public static final String USE_OAUTH_FOR = "USE_OAUTH_FOR";
	public static final String OAUTH_FRONTEND = "frontend";
	public static final String OAUTH_BACKEND = "backend";
	public static final String DEFAULT_OAUTH_PROVIDER = "DEFAULT_OAUTH_PROVIDER";
	public static final String OAUTH_PROVIDER_KEY = "oauthProvider";
	public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
	public static final String UTF_8 = "UTF-8";
	public static final String FEMALE = "female";
	public static final String GENDER = "gender";
	public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = "javax.servlet.forward.request_uri";
	public static final String REFERRER = "referrer";
	public static final String LOCATION = "Location";
	public static final String CODE_PARAM_KEY = "code";
	private static String CALLBACK_URL;
	private static String ROLES_TO_ADD;
	private final LoginServiceAPI loginServiceAPI;
	private final boolean isFrontEnd;
	private final boolean isBackEnd;
	private final boolean rememberMe;


	public OAuth2Servlet() {

		final String  useFor = getProperty(USE_OAUTH_FOR, StringUtils.EMPTY).toLowerCase();
		this.rememberMe     = "true".equalsIgnoreCase(getProperty("rememberMe", "true"));
		this.isFrontEnd		 = useFor.contains (OAUTH_FRONTEND);
		this.isBackEnd  	 = useFor.contains (OAUTH_BACKEND);
		this.loginServiceAPI = APILocator.getLoginServiceAPI();
	}

	private void doLog (final String msg) {
		System.out.println(msg);
	}


	@Override
	public void service(final ServletRequest req,
						final ServletResponse res) throws IOException, ServletException {

		final HttpServletResponse response               = (HttpServletResponse) res;
		final HttpServletRequest request                = (HttpServletRequest) req;
		final HttpSession session  = request.getSession(false);
		final User user            	   = this.getUser(request, session); // get our user
		final String callbackHost    	   = this.getCallbackHost(request);
		final String oauthProvider    	   = this.getOauthProvider(request, session);
		final Api provider 			   = this.getProvider(oauthProvider);
		final String proName    	    	   = provider.getClass().getSimpleName();
		final String apiKey				   = getProperty(proName + "_API_KEY");
		final String apiSecret 		       = getProperty(proName + "_API_SECRET");
		final String protectedResourceUrl   = getProperty(proName + "_PROTECTED_RESOURCE_URL");
		final String scope				   = getProperty(proName + "_SCOPE");
		final String firstNameProp		   = getProperty(proName + "_FIRST_NAME_PROP");
		final String lastNameProp  		   = getProperty(proName + "_LAST_NAME_PROP");

		// if the user is already logged in
		if (user == null) {
			doLog("OAuth2Servlet: User is null");
			// set up Oauth service
			OAuthService service = new ServiceBuilder()
					.provider(provider.getClass())
					.apiKey(apiKey)
					.apiSecret(apiSecret)
					.scope(scope)
					.callback(callbackHost + CALLBACK_URL)
					.build();

			if (null != request.getParameter(CODE_PARAM_KEY)) {

				doLog("OAuth2Servlet: code param found, doing callback");
				try {

					this.doCallback(request, response, service,
							protectedResourceUrl, firstNameProp, lastNameProp);

					// redirect onward!
					final HttpSession httpSession = request.getSession(true);
					final String authorizationUrl = (String)httpSession.getAttribute(OAUTH_REDIRECT);

					if (authorizationUrl == null) {
						this.alreadyLoggedIn(response);
					} else {
						httpSession.removeAttribute(OAUTH_REDIRECT);
						response.sendRedirect(authorizationUrl);
					}
				} catch (Exception e) {

					Logger.debug(this, e.getMessage(), e);
					throw new ServletException(e);
				}

			} else {
				// Send for authorization
				doLog("OAuth2Servlet: sending for authorization");
				this.sendForAuthorization(request, response, service);
			}
		} else {

			this.alreadyLoggedIn(response);
		}
	} // service.

	private void alreadyLoggedIn(HttpServletResponse response) throws IOException {

		doLog("OAuth2Servlet: already login, redirecting to /dotAdmin");
		Logger.error(this.getClass(), "Already logged in, redirecting home");

		response.sendRedirect((this.isBackEnd)?"/dotAdmin":"/?already-logged-in");
	}

	private Api getProvider (final String oauthProvider) throws ServletException {

		Api provider = null;

		try {

			provider = (Api) Class.forName(oauthProvider).newInstance();
		} catch (Exception e1) {
			Logger.error(this, e1.getMessage(), e1);
			throw new ServletException(e1);
		}

		return provider;
	} // getProvider.

	private User getUser(final HttpServletRequest request, final HttpSession session) {

		User user = null;

		try {
			if (null != session) {

				if (this.isFrontEnd) {
					user = (User) session.getAttribute(com.dotmarketing.util.WebKeys.CMS_USER);
					doLog("OAuth2Servlet: CMS USER IS: " + user);
				}

				if (this.isBackEnd && null == user) {

					try {
						user = com.liferay.portal.util.PortalUtil.getUser(request);
						doLog("OAuth2Servlet: DOT8 USER IS: " + user);
					} catch (Exception nsue) {
						Logger.warn(this, "Exception trying to getUser: " + nsue.getMessage(), nsue);
					}
				}
			}
		} catch (Exception nsue) {
			Logger.warn(this, "Exception trying to getUser: " + nsue.getMessage(), nsue);
		}

		return user;
	} // getUser.

	private String getCallbackHost(final HttpServletRequest request) {

		return request.getScheme() + "://" + ((request.getServerPort() == 80 || request.getServerPort() == 443) ?
						request.getServerName() : request.getServerName()+":"+request.getServerPort());
	} // getCallbackHost.

	@Override
	public void init() throws ServletException {

		ROLES_TO_ADD = OAuthPropertyBundle.getProperty("ROLES_TO_ADD");
		CALLBACK_URL = OAuthPropertyBundle.getProperty("CALLBACK_URL");
	}

	/**
	 * This method gets the user from the remote service and either creates them
	 * in Dotcms and/or updates
	 * 
	 * @param request
	 * @param service
	 * @return User
	 * @throws DotDataException
	 */
	private User doCallback(final HttpServletRequest request, final HttpServletResponse response,
							final OAuthService service, final String callBackUrl, final String firstNameProp,
							final String lastNameProp) throws DotDataException {

		final Verifier verifier = new Verifier(request.getParameter("code"));
		final Token accessToken = service.getAccessToken(null, verifier);

		doLog("OAuth2Servlet: Got the Access Token!");

		final OAuthRequest quest = new OAuthRequest(Verb.GET, callBackUrl);
		quest.addHeader("Authorization", "Bearer " + accessToken.getToken());
		service.signRequest(accessToken, quest);

		final Response jsonResponse = quest.send();

		final JSONObject json = (JSONObject) new JSONTool().generate(jsonResponse.getBody());

		User sys = APILocator.getUserAPI().getSystemUser();
		User user = null;

		try {

			doLog("OAuth2Servlet: Loading an user!");
			user = APILocator.getUserAPI().loadByUserByEmail(json.getString("email"), sys, false);
			doLog("OAuth2Servlet: User loaded!");
		} catch (Exception e) {
			Logger.warn(this, "No matching user, creating");
		}

		if (user == null) {
			try {
				doLog("OAuth2Servlet: User not found, creating one!");
				user = this.createUser(firstNameProp, lastNameProp, json, sys);
			} catch (Exception e) {
				Logger.warn(this, "Error creating user:" + e.getMessage(), e);
				throw new DotDataException(e.getMessage());
			}
		}

		if (user.isActive()) {

			doLog("OAuth2Servlet: User is active, adding roles!");
			final StringTokenizer st = new StringTokenizer(ROLES_TO_ADD, ",;");
			while (st.hasMoreElements()) {

				this.addRole(user, st);
			}

			doLog("OAuth2Servlet: Doing login!");
			this.loginServiceAPI.doCookieLogin(PublicEncryptionFactory.encryptString
					(user.getUserId()), request, response, this.rememberMe);

			if (isBackEnd) {
				doLog("OAuth2Servlet: Finish BE login!");
				PrincipalThreadLocal.setName(user.getUserId());
				final HttpSession httpSession = request.getSession(true);
				httpSession.setAttribute(WebKeys.USER_ID, user.getUserId());
			}
		}

		return user;
	} //doCallback.

	private void addRole(final User user, final StringTokenizer st) throws DotDataException {

		final String roleKey = st.nextToken().trim();
		final Role role = APILocator.getRoleAPI().loadRoleByKey(roleKey);
		if (role != null && !APILocator.getRoleAPI().doesUserHaveRole(user, role)) {

            APILocator.getRoleAPI().addRoleToUser(role, user);
        }
	} // addRole.

	private User createUser(final String firstNameProp,
							final String lastNameProp,
							final JSONObject json,
							final User sys) throws UnsupportedEncodingException, JSONException, DotDataException, DotSecurityException {

		final String userId    = UUIDGenerator.generateUuid();
		final String email     = new String(json.getString("email").getBytes(),   UTF_8);
		final String lastName  = new String(json.getString(lastNameProp).getBytes(),   UTF_8);
		final String firstName = new String(json.getString(firstNameProp).getBytes(),  UTF_8);

		final User user = APILocator.getUserAPI().createUser(userId, email);

		user.setFirstName(firstName);
		user.setLastName(lastName);
		user.setActive(true);

		user.setCreateDate(new Date());
		if (!json.isNull(GENDER)) {
			user.setFemale(FEMALE.equals(json.getString(GENDER)));
		}
		user.setPassword(PublicEncryptionFactory.digestString(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
		user.setPasswordEncrypted(true);

		APILocator.getUserAPI().save(user, sys, false);
		return user;
	} // createUser.

	private void sendForAuthorization(final HttpServletRequest request,
									  final HttpServletResponse response,
									  final OAuthService service) throws IOException {

		String retUrl = (String) request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI);

		if (request.getSession().getAttribute(OAUTH_REDIRECT) != null) {
			retUrl = (String) request.getSession().getAttribute(OAUTH_REDIRECT);
		}

		if (request.getParameter(REFERRER) != null) {
			retUrl = request.getParameter(REFERRER);
		}

		request.getSession().setAttribute(OAUTH_REDIRECT, retUrl);

		final String authorizationUrl = service.getAuthorizationUrl(null);
		doLog("OAuth2Servlet: Redirecting for authentication to: " + authorizationUrl);
		response.sendRedirect(authorizationUrl);
	}

	private String getOauthProvider (final HttpServletRequest request, final HttpSession session) {

		String oauthProvider = getProperty(DEFAULT_OAUTH_PROVIDER);

		if (null != session && session.getAttribute(OAUTH_PROVIDER_KEY) != null) {
			oauthProvider = (String) session.getAttribute(OAUTH_PROVIDER_KEY);
		}

		if (request.getParameter(OAUTH_PROVIDER_KEY) != null) {
			oauthProvider = request.getParameter(OAUTH_PROVIDER_KEY);
		}

		if (null != session) {
			session.setAttribute(OAUTH_PROVIDER_KEY, oauthProvider);
		}

		return oauthProvider;
	} // getOauthProvider.

	public void destroy() {

	}

} // E:O:F:OAuth2Servlet.
