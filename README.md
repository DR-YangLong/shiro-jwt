# Spring 集成Shiro 实现JWT

2023年端午节开发的又一个轮子。

基于shiro和spring，添加JWT支持。自定义依赖版本可以修改pom中相关spring，shiro依赖的版本。

## 支持算法

> HMAC算法：HS256,HS384,HS512

> RSA算法

> EC有限支持:EC P-256,EC P-384,EC P-521

底层库[nimbus-jose](https://connect2id.com/products/nimbus-jose-jwt)

## 目的

根据请求头中传过来的JWT，自动适配签名算法，使用配置文件中配置的密钥，对JWT进行验签和反解进行登录，并绑定系统用户及权限

## 使用

由于提供了JWT配置，需要提供JWT在请求头中的名称，token的前缀等信息。另外组件可以支持多Realm和多自定义Filter，需要遵守一些约定。
组件默认会在definitions末尾追加/**=jwt，未在配置文件中definitions指定的请求地址，全部使用JWTFilter进行拦截认证。

### 属性配置

```yaml
shiro:
  # 认证中心登录地址
  loginUrl: "http://127.0.0.1:9090/login"
  # 未认证响应地址
  unauthorizedUrl: "/401"
  # 自定义shiro扩展filter
  filters: '{"oauth2":"com.example.shiro.filter.OAuth2Filter"}'
  # ShiroFilterChainDefinitions
  definitions: '{"/uer/info": "authc","/system/menu": "roles[manager]","/system/user": "roles[manager,admin]","/system/roles": "perms[manager]"}'
  jwt:
    # JWT请求头名称，默认Authorization
    header: "X-NODE-ID"
    # JWT前缀，假如token为3ef6ej，则请求头为[X-NODE-ID:Must 3ef6ej]
    bearer: "Must"
    # JWT签发者
    issuer: "AuthCenter"
    # JWT有效期
    expirationTime: 15M
    # RSA或EC模式下的私钥
    privateKey: ""
    # RSA或EC模式下的公钥
    publicKey: ""
    # EC模式下的算法模式：P_256，P_384，P_521。注意不同算法模式在生成密钥时要指定算法。
    dsaCurve:
    # HMAC密钥，建议长度最少128
    hacSecretKey: ""
```

组件进行JWT验签时会根据JWT头部获取算法信息，然后使用相同的算法和配置的密钥进行验签。但是**请注意**
，此组件仅支持上文说的算法种类。另外不同算法对应的密钥不同，在密钥生成的时候请注意根据需要指定算法。

### 扩展

此组件支持扩展自定义认证Filter和Realm进行认证授权。需要遵守以下规则：

> Filter继承AuthenticatingFilter或AuthorizationFilter，不能注解spring
> stereotype包的注解，提供无参构造函数，也就是不能注入容器，属性字段可以使用@Resource，@Autowire等注入注解，然后配置到配置文件中。注意Filter的继承上限是AccessControlFilter。

> Realm继承AuthorizingRealm，使用@Bean注入容器

> 扩展返回用户为BaseUser或其子类

> 动态替换密钥，可注入JwtProperties然后修改密钥，JWT生成和验签的时候调用

## shiro

```text
1. ShiroFilterFactoryBean使用SecurityManager，FilterChainManager(filters，filterChainDefinitionMap生成)
   创建SpringShiroFilter(继承自AbstractShiroFilter)，
2. SpringShiroFilter为SecurityUtils设置SecurityManager并代理了shiro的filterChain，运行时，在doFilterInternal(
   父Filter的doFilter调用)中创建线程上下文Subject，并调用Subject.execute执行shiro的filterChain，进行认证授权
3. Shiro的Filter继承树AdviceFilter->PathMatchingFilter->AccessControlFilter->AuthenticationFilter，AuthorizationFilter
4. AuthenticationFilter->AuthenticatingFilter负责认证，默认实现的有BasicHttpAuthenticationFilter-HTTP
   BASIC认证，BearerHttpAuthenticationFilter-HTTP BEARER认证，FormAuthenticationFilter-表单认证
5. AuthorizationFilter负责权限检查，默认实现的有HostFilter-IP白名单，SslFilter-SSL请求名单，PortFilter-请求端口名单，HttpMethodPermissionFilter-请求方法白名单，PermissionsAuthorizationFilter-字符串权限检查，RolesAuthorizationFilter-角色权限检查
6. 认证和授权的核心方法在AccessControlFilter#onPreHandle方法，此方法根据isAccessAllowed||onAccessDenied的返回值判断请求是否向下执行。
7. 对于认证的Filter，继承AuthenticatingFilter，里面已经定义了流程，1)createToken；2)执行登录executeLogin；3)
   处理登录结果。扩展的filter只要createToken，isAccessAllowed，onAccessDenied方法，在isAccessAllowed或者onAccessDenied方法中返回调用executeLogin父方法的返回值。
8. 对于授权检查的Filter，继承AuthorizationFilter实现isAccessAllowed方法，在其内自定义权限检查逻辑，放行返回true，拦截返回false即可。
9. 登录认证流程，Subject.login方法，委托给SecurityManager的login方法，调用Authenticator的authenticate方法，Authenticator最终调用AuthenticatingRealm的getAuthenticationInfo获取用户信息，如果获取成功，则代表登录成功。
10. 授权流程（默认），Subject有众多的isPermitted，hasRole等权限检查方法，都是委托给SecurityManager同名方法执行，SecurityManager调用Authorizer相关方法，Authorizer最终通过AuthorizingRealm的getAuthorizationInfo获取用户权限并判断用户是否有权限。
```

