package cn.cordys.common.security;

import cn.cordys.common.util.CommonBeanFactory;
import cn.cordys.crm.system.service.UserKeyService;
import cn.cordys.crm.system.service.UserLoginService;
import cn.cordys.security.SessionConstants;
import cn.cordys.security.SessionUser;
import cn.cordys.security.SessionUtils;
import cn.cordys.security.UserDTO;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * 自定义过滤器，用于处理 Web 应用中的 API 密钥认证。
 * 继承 AnonymousFilter 支持 API 密钥认证和常规会话认证。
 */
@Slf4j
public class ApiKeyFilter extends AnonymousFilter {

    private static final String NO_PASSWORD = "no_pass"; // 默认的密码，用于 API 密钥认证

    /**
     * 在处理请求之前调用。该方法检查请求是否使用 API 密钥。
     * 如果没有 API 密钥且用户未认证，则允许请求通过。
     * 如果提供了 API 密钥，则使用该密钥尝试认证用户。
     *
     * @param request     Servlet 请求
     * @param response    Servlet 响应
     * @param mappedValue 过滤器链中的映射值
     *
     * @return 如果请求应该继续处理返回 true，否则返回 false
     */
    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);

        // 如果不是 API 密钥请求且用户未认证，允许请求继续:
        if (!ApiKeyHandler.isApiKeyCall(httpRequest) && !SecurityUtils.getSubject().isAuthenticated()) {
            return true;
        }

        // 处理 API 密钥认证
        if (!SecurityUtils.getSubject().isAuthenticated()) {
            log.info("Attempting API key authentication for URI: {}", httpRequest.getRequestURI());

            // 优先从 X-Access-Key/X-Secret-Key 头直接验证
            String userId = getUserIdFromApiKey(httpRequest);
            if (userId == null) {
                // 回退到 CommonBeanFactory.getUser()（处理 Authorization 头）
                userId = CommonBeanFactory.getUser(httpRequest);
            }
            log.info("API key authentication result - userId: {}", userId);
            if (StringUtils.isNotBlank(userId)) {
                // 使用 API 密钥中的用户 ID 进行认证，密码设置为默认值
                SecurityUtils.getSubject().login(new UsernamePasswordToken(userId, NO_PASSWORD));
                log.info("API key authentication successful for user: {}", userId);

                // 设置用户信息到 Session（API Key 认证需要）
                setupUserSession(userId);
            }
        }

        // 如果仍未认证，设置响应头为无效状态
        if (!SecurityUtils.getSubject().isAuthenticated()) {
            log.info("API key authentication failed for URI: {}", httpRequest.getRequestURI());
            ((HttpServletResponse) response).setHeader(SessionConstants.AUTHENTICATION_STATUS, "invalid");
        }

        return true;
    }

    /**
     * 从 X-Access-Key / X-Secret-Key 头直接验证 API Key
     */
    private String getUserIdFromApiKey(HttpServletRequest request) {
        String accessKey = request.getHeader("X-Access-Key");
        String secretKey = request.getHeader("X-Secret-Key");
        if (StringUtils.isBlank(accessKey) || StringUtils.isBlank(secretKey)) {
            return null;
        }
        try {
            UserKeyService userKeyService = CommonBeanFactory.getBean(UserKeyService.class);
            if (userKeyService == null) {
                log.info("UserKeyService not available");
                return null;
            }
            var userKey = userKeyService.getUserKey(accessKey);
            if (userKey == null) {
                log.info("UserKey not found for accessKey: {}", accessKey);
                return null;
            }
            if (!Boolean.TRUE.equals(userKey.getEnable())) {
                log.info("UserKey is disabled: {}", accessKey);
                return null;
            }
            if (Boolean.FALSE.equals(userKey.getForever()) && userKey.getExpireTime() != null
                    && userKey.getExpireTime() < System.currentTimeMillis()) {
                log.info("UserKey is expired: {}", accessKey);
                return null;
            }
            if (secretKey.equals(userKey.getSecretKey())) {
                return userKey.getCreateUser();
            } else {
                log.info("Secret key mismatch for accessKey: {}", accessKey);
                return null;
            }
        } catch (Exception e) {
            log.error("Error validating API key: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * 设置用户信息到 Session
     */
    private void setupUserSession(String userId) {
        try {
            UserLoginService userLoginService = CommonBeanFactory.getBean(UserLoginService.class);
            if (userLoginService != null) {
                UserDTO userDTO = userLoginService.authenticateUser(userId);
                if (userDTO != null) {
                    SessionUser sessionUser = SessionUser.fromUser(userDTO, SessionUtils.getSessionId());
                    SessionUtils.putUser(sessionUser);
                    log.info("Session user set for API key auth: {}", userId);
                }
            }
        } catch (Exception e) {
            log.error("Failed to setup user session for API key auth: {}", e.getMessage(), e);
        }
    }

    /**
     * 在请求处理之后调用。此方法用于处理 API 密钥退出逻辑。
     * 如果是 API 密钥请求并且用户已认证，则注销当前用户。
     *
     * @param request  Servlet 请求
     * @param response Servlet 响应
     */
    @Override
    protected void postHandle(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);

        // 如果是 API 密钥请求且用户已认证，则注销用户
        if (ApiKeyHandler.isApiKeyCall(httpRequest) && SecurityUtils.getSubject().isAuthenticated()) {
            SecurityUtils.getSubject().logout();
        }
    }
}
