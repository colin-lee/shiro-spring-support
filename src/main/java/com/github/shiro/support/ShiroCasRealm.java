package com.github.shiro.support;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cas.CasAuthenticationException;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * @author colinli
 * @since 13-11-8 下午8:20
 */
public class ShiroCasRealm extends CasRealm {
  private static final Logger LOG = LoggerFactory.getLogger(ShiroCasRealm.class);

  /**
   * Authenticates a user and retrieves its information.
   *
   * @param token the authentication token
   * @throws org.apache.shiro.authc.AuthenticationException if there is an error during authentication.
   */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    CasToken casToken = (CasToken) token;
    if (token == null) {
      return null;
    }

    String ticket = (String) casToken.getCredentials();
    if (!StringUtils.hasText(ticket)) {
      return null;
    }

    TicketValidator ticketValidator = ensureTicketValidator();

    try {
      // contact CAS server to validate service ticket
      Assertion casAssertion = ticketValidator.validate(ticket, getCasService());
      // get principal, user id and attributes
      AttributePrincipal casPrincipal = casAssertion.getPrincipal();
      String userId = casPrincipal.getName();
      Map<String, Object> attributes = casPrincipal.getAttributes();
      LOG.info("Validate ticket : {} in CAS server : {} to retrieve user : {}, attributes: {}", ticket, getCasServerUrlPrefix(), userId, attributes);
      // refresh authentication token (user id + remember me)
      casToken.setUserId(userId);
      String rememberMeAttributeName = getRememberMeAttributeName();
      String rememberMeStringValue = (String) attributes.get(rememberMeAttributeName);
      boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
      if (isRemembered) {
        casToken.setRememberMe(true);
      }
      // create simple authentication info
      ShiroUser user = new ShiroUser((String) attributes.get("username"));
      List<Object> principals = CollectionUtils.asList(user, attributes);
      PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());
      LOG.info("principal: {}", principalCollection);
      return new SimpleAuthenticationInfo(principalCollection, ticket);
    } catch (TicketValidationException e) {
      LOG.error("{}", ticket, e);
      throw new CasAuthenticationException("Unable to validate ticket [" + ticket + "]", e);
    }
  }

  @Override
  protected TicketValidator createTicketValidator() {
    return new Cas30ServiceTicketValidator(getCasServerUrlPrefix());
  }

  public void logout() {
    try {
      Subject subject = SecurityUtils.getSubject();
      subject.logout();
      clearAllCachedAuthorizationInfo();
    } catch (Exception e) {
      LOG.error("cannot logout", e);
    }
  }

  /* 更新用户授权信息缓存 */
  public void clearCachedAuthorizationInfo(String principal) {
    SimplePrincipalCollection principals = new SimplePrincipalCollection(principal, getName());
    clearCachedAuthorizationInfo(principals);
  }

  /* 清除所有用户授权信息缓存 */
  public void clearAllCachedAuthorizationInfo() {
    Cache<Object, AuthorizationInfo> cache = getAuthorizationCache();
    if (cache != null) {
      LOG.info("cache: {}", cache);
      for (Object key : cache.keys()) {
        LOG.info("remove {}", key);
        cache.remove(key);
      }
    }
  }

  public String getCurrentUserName() {
    ShiroUser user = (ShiroUser) SecurityUtils.getSubject().getPrincipal();
    return user.getUsername();
  }

  public ShiroUser getCurrentUser() {
    return (ShiroUser) SecurityUtils.getSubject().getPrincipal();
  }
}
