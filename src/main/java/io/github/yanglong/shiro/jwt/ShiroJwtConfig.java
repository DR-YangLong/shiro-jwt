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

package io.github.yanglong.shiro.jwt;

import io.github.yanglong.shiro.jwt.filter.JwtHttpAuthenticationFilter;
import io.github.yanglong.shiro.jwt.realm.JwtRealm;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import javax.servlet.Filter;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 用途描述：配置类
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/24
 */
@Slf4j
@Configuration
public class ShiroJwtConfig {
    
    @Bean
    public JwtRealm jwtRealm(JwtProperties jwtProperties, JwtLocalUserService jwtLocalUserService) {
        return new JwtRealm(jwtProperties, jwtLocalUserService);
    }
    
    /**
     * 开启shiro aop注解支持
     */
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        return new DefaultAdvisorAutoProxyCreator();
    }
    
    /**
     * shiro 生命周期
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }
    
    /**
     * 开启shiro aop权限注解支持
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }
    
    @Bean
    public Authenticator authenticator() {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return authenticator;
    }
    
    @Bean("securityManager")
    public SecurityManager securityManager(List<Realm> realms) {
        DefaultWebSecurityManager securityManager = this.createSecurityManager();
        securityManager.setAuthenticator(this.authenticator());
        securityManager.setRealms(realms);
        return securityManager;
    }
    
    @Bean(value = "shiroFilter")
    @DependsOn()
    protected ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager,
            ShiroFilterChainDefinition shiroFilterChainDefinition, JwtProperties jwtProperties,
            ShiroSpringContextAware shiroSpringContextAware) {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        
        filterFactoryBean.setLoginUrl(jwtProperties.getLoginUrl());
        filterFactoryBean.setUnauthorizedUrl(jwtProperties.getUnauthorizedUrl());
        
        filterFactoryBean.setSecurityManager(securityManager);
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        //自定义的Filter
        Map<String, Filter> map = filterFactoryBean.getFilters();
        map.put("jwt", new JwtHttpAuthenticationFilter(jwtProperties.getTokenHeader(), jwtProperties.getTokenBearer()));
        //处理自定义的filter
        if (null == shiroSpringContextAware.applicationContext()) {
            throw new RuntimeException("无法初始化");
        }
        Map<String, String> extendMap = jwtProperties.getFilters();
        fillExtendMap(extendMap, map);
        return filterFactoryBean;
    }
    
    /**
     * 读取配置中的特殊认证配置，其他配置全部需要JWT认证
     */
    @Bean("shiroFilterChainDefinition")
    public ShiroFilterChainDefinition shiroFilterChainDefinition(JwtProperties jwtProperties) {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        Map<String, String> definitions = jwtProperties.getDefinitions();
        String endDefinition = "jwt";
        if (!CollectionUtils.isEmpty(definitions)) {
            endDefinition = Optional.ofNullable(definitions.get("/**")).orElse(endDefinition);
            chainDefinition.addPathDefinitions(definitions);
        }
        chainDefinition.addPathDefinition("/favicon.ico","anon");
        chainDefinition.addPathDefinition("/**", endDefinition);
        return chainDefinition;
    }
    
    protected DefaultWebSecurityManager createSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setSubjectDAO(this.subjectDAO());
        securityManager.setSubjectFactory(this.subjectFactory());
        RememberMeManager rememberMeManager = this.rememberMeManager();
        if (rememberMeManager != null) {
            securityManager.setRememberMeManager(rememberMeManager);
        }
        
        return securityManager;
    }
    
    protected SubjectDAO subjectDAO() {
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        subjectDAO.setSessionStorageEvaluator(this.sessionStorageEvaluator());
        return subjectDAO;
    }
    
    protected SessionStorageEvaluator sessionStorageEvaluator() {
        DefaultSessionStorageEvaluator storageEvaluator = new DefaultSessionStorageEvaluator();
        storageEvaluator.setSessionStorageEnabled(false);
        return storageEvaluator;
    }
    
    protected SubjectFactory subjectFactory() {
        return new DefaultWebSubjectFactory();
    }
    
    protected RememberMeManager rememberMeManager() {
        return null;
    }
    
    /**
     * 创建filter并添加m
     */
    protected void fillExtendMap(Map<String, String> namedFilter, Map<String, Filter> filterMap) {
        if (!CollectionUtils.isEmpty(namedFilter)) {
            namedFilter.forEach((k, v) -> {
                try {
                    Class<?> clazz = Class.forName(v);
                    if (isAccessControlFilter(clazz)) {
                        String beanName = k + "shiroFilter";
                        Filter filter = (Filter) ShiroSpringContextAware.registerGetBean(beanName, clazz);
                        filterMap.put(k, filter);
                        ShiroSpringContextAware.removeBean(beanName);
                    } else {
                        log.error("can't load custom shiro filter:{}={},it is not a AccessControlFilter", k, v);
                    }
                } catch (ClassNotFoundException e) {
                    log.error("can't load custom shiro filter:{}={}", k, v, e);
                }
            });
        }
    }
    
    protected static boolean isAccessControlFilter(Class<?> filter) {
        return AccessControlFilter.class.isAssignableFrom(filter);
    }
}
