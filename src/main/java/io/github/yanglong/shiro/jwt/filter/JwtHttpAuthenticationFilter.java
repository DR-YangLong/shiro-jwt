/*
 * Copyright 2023 YangLong
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package io.github.yanglong.shiro.jwt.filter;

import io.github.yanglong.shiro.jwt.authc.JwtToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 用途描述：shiro扩展核心执行类，判断请求是否向下继续执行。从request中创建token，使用token进行登录，登录后进行鉴权，对登录和鉴权结果进行处理
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/24
 */
@Slf4j
public class JwtHttpAuthenticationFilter extends AuthenticatingFilter {
    
    private final String headerName;
    
    private final String bearer;
    
    public JwtHttpAuthenticationFilter(String headerName, String bearer) {
        this.headerName = headerName;
        this.bearer = bearer;
    }
    
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        String token = null;
        if (isLoginAttempt(request)) {
            String header = getAuthHeader(request);
            token = extractJwt(header);
        }
        return new JwtToken(token);
    }
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean loggedIn = false;
        if (isLoginAttempt(request)) {
            loggedIn = executeLogin(request, response);
        }
        if (!loggedIn) {
            sendChallenge(request, response);
        }
        return loggedIn;
    }
    
    /**
     * 判断请求头中是否有JWT
     *
     * @param request 请求
     * @return 有-true,没有-false
     */
    protected boolean isLoginAttempt(ServletRequest request) {
        String header = getAuthHeader(request);
        return StringUtils.isNotBlank(header) && header.toLowerCase().startsWith(bearer.toLowerCase());
        
    }
    
    /**
     * 提前请求头
     *
     * @param request 请求
     * @return 请求头
     */
    protected String getAuthHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(headerName);
    }
    
    /**
     * 响应401
     */
    protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
        log.debug("Authentication required: sending 401 Authentication challenge response.");
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }
    
    /**
     * 从请求头值中分离出JWT
     */
    protected String extractJwt(String header) {
        if (StringUtils.isNoneBlank(header)) {
            if (StringUtils.isNoneBlank(bearer)) {
                //去除前缀
                int length = bearer.length() + 1;
                if (header.length() > length) {
                    header = header.substring(length);
                } else {
                    header = "";
                    log.debug("通用token认证-获取token-无效的Token:[token:{}]", header);
                }
            }
        } else {
            header = null;
        }
        return header;
    }
}
