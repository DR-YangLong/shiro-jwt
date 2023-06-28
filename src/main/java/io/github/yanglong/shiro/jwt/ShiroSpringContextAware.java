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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.AbstractRefreshableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * 用途描述：获取上下文，注册对象到容器，删除容器内对象
 *
 * @author YangLong
 * @version V1.0
 * @since 2021/2/23
 */
@Slf4j
@Component("shiroSpringContextAware")
@Order(value = Ordered.HIGHEST_PRECEDENCE)
public class ShiroSpringContextAware implements ApplicationContextAware {
    
    private static ApplicationContext applicationContext;
    
    /**
     * 获取applicationContext
     */
    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }
    
    public ApplicationContext applicationContext() {
        return applicationContext;
    }
    
    @Override
    public void setApplicationContext(@Nullable ApplicationContext applicationContext) throws BeansException {
        log.info("inject ApplicationContext to OnsContextAware!");
        ShiroSpringContextAware.applicationContext = applicationContext;
    }
    
    /**
     * 从容器中移除Bean
     *
     * @param beanName 移除的Bean名称
     */
    public static void removeBean(String beanName) {
        try {
            BeanDefinitionRegistry beanDefReg = (DefaultListableBeanFactory) ((AbstractApplicationContext) getApplicationContext()).getBeanFactory();
            beanDefReg.getBeanDefinition(beanName);
            beanDefReg.removeBeanDefinition(beanName);
        } catch (NoSuchBeanDefinitionException e) {
            log.error("无法移除名为{}在IOC中的实例。", beanName, e);
        }
    }
    
    /**
     * 向Spring容器中注入bean，构造器注入。然后获取。
     *
     * @param beanName        bean在容器中的名称
     * @param beanClass       bean Class对象
     * @param constructorArgs 构造函数参数，需按构造函数参数顺序传入
     * @param <T>             注入的class类型
     */
    public static <T> T registerGetBean(String beanName, Class<T> beanClass, Object... constructorArgs) {
        registerBean(beanName, beanClass, constructorArgs);
        return getBean(beanName, beanClass);
    }
    
    /**
     * 向Spring容器中注入bean，构造器注入
     *
     * @param beanName        bean在容器中的名称
     * @param beanClass       bean Class对象
     * @param constructorArgs 构造函数参数，需按构造函数参数顺序传入
     * @param <T>             注入的class类型
     */
    public static <T> void registerBean(String beanName, Class<T> beanClass, Object... constructorArgs) {
        if (Objects.isNull(beanClass)) {
            if (log.isDebugEnabled()) {
                log.debug("beanClass为空，无法注入Bean:{}", beanName);
            }
        }
        //构建BeanDefinitionBuilder
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(beanClass);
        //添加Bean对象构造函数的参数
        Optional.ofNullable(constructorArgs)
                .ifPresent(argArr -> Arrays.stream(argArr).forEach(builder::addConstructorArgValue));
        //从builder中获取到BeanDefinition对象
        BeanDefinition beanDefinition = builder.getRawBeanDefinition();
        try {
            //获取spring容器中的IOC容
            DefaultListableBeanFactory defaultListableBeanFactory = (DefaultListableBeanFactory) getApplicationContext().getAutowireCapableBeanFactory();
            //向IOC容器中注入bean对象
            defaultListableBeanFactory.registerBeanDefinition(beanName, beanDefinition);
        } catch (IllegalStateException | BeanDefinitionStoreException e) {
            log.error("无法注入类型为{}的Bean:{}。", beanClass.getName(), beanName, e);
        }
    }
    
    /**
     * 将实例化的Bean注入到Spring容器
     *
     * @param beanName Bean在容器中的名称，需要唯一
     * @param bean     要注入的Bean
     * @param <T>      注入的Bean类型
     */
    public static <T> void registerBean(String beanName, T bean) {
        ConfigurableListableBeanFactory beanFactory = ((AbstractRefreshableApplicationContext) getApplicationContext()).getBeanFactory();
        beanFactory.registerSingleton(beanName, bean);
    }
    
    /**
     * 通过类名获取对象
     *
     * @param name 类名称
     * @return 类在容器中对象
     */
    public static Object getBean(String name) {
        return getApplicationContext().getBean(name);
    }
    
    /**
     * 通过类获取此类在容器中的对象
     *
     * @param clazz 类名
     * @param <T>   泛型类
     * @return 类型对象
     */
    public static <T> T getBean(Class<T> clazz) {
        return getApplicationContext().getBean(clazz);
    }
    
    /**
     * 通过对象name,以及Clazz返回容器中指定的Bean
     *
     * @param name  对象名
     * @param clazz 类型
     */
    public static <T> T getBean(String name, Class<T> clazz) {
        return getApplicationContext().getBean(name, clazz);
    }
}
