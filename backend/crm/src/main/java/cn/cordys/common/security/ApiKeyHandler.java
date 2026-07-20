package cn.cordys.common.security;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;

/**
 * 处理 API 密钥验证的工具类，包括获取用户、验证请求是否包含 API 密钥以及验证签名的功能。
 */
public class ApiKeyHandler {

    public static final String AUTHORIZATION = "Authorization"; // 授权字段
    public static final String X_ACCESS_KEY = "X-Access-Key"; // CordysCRM-skills 使用的头
    public static final String X_SECRET_KEY = "X-Secret-Key"; // CordysCRM-skills 使用的头

    /**
     * 判断请求是否包含有效的 API 密钥和签名。
     * 支持两种格式：
     * 1. Authorization: AccessKey:SecretKey
     * 2. X-Access-Key: xxx / X-Secret-Key: xxx
     *
     * @param request HTTP 请求
     *
     * @return 如果请求包含有效的 API 密钥和签名，返回 true；否则返回 false
     */
    public static Boolean isApiKeyCall(HttpServletRequest request) {
        if (request == null) {
            return false;
        }

        // 检查 Authorization 头
        String authorization = request.getHeader(AUTHORIZATION);
        if (!StringUtils.isBlank(authorization) && authorization.split(":").length >= 2) {
            return true;
        }

        // 检查 X-Access-Key / X-Secret-Key 头
        String accessKey = request.getHeader(X_ACCESS_KEY);
        String secretKey = request.getHeader(X_SECRET_KEY);
        if (!StringUtils.isBlank(accessKey) && !StringUtils.isBlank(secretKey)) {
            return true;
        }

        return false;
    }
}
