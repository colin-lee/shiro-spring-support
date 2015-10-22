package com.github.shiro.support;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.velocity.tools.Scope;
import org.apache.velocity.tools.config.DefaultKey;
import org.apache.velocity.tools.config.ValidScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.util.Collection;

/**
 * @author colinli
 * @since 13-11-3 下午6:13
 */
@DefaultKey("shiro")
@ValidScope(Scope.APPLICATION)
public class ShiroVelocitySupport {
  private static final Logger LOG = LoggerFactory.getLogger(ShiroVelocitySupport.class);

  /* 验证是否为已认证通过的用户，不包含已记住的用户，这是与 isUser 标签方法的区别所在。 */
  public boolean isAuthenticated() {
    Subject subject = SecurityUtils.getSubject();
    return subject != null && subject.isAuthenticated();
  }

  /* 验证是否为未认证通过用户，与 isAuthenticated 标签相对应，与 isGuest 标签的区别是，该标签包含已记住用户。 */
  public boolean isNotAuthenticated() {
    Subject subject = SecurityUtils.getSubject();
    return subject == null || !subject.isAuthenticated();
  }

  /* 验证当前用户是否为“访客”，即未认证（包含未记住）的用户。 */
  public boolean isGuest() {
    Subject subject = SecurityUtils.getSubject();
    return subject == null || subject.getPrincipal() == null;
  }

  /* 验证当前用户是否认证通过或已记住的用户。 */
  public boolean isUser() {
    Subject subject = SecurityUtils.getSubject();
    return subject != null && subject.getPrincipal() != null;
  }

  /* 获取当前用户 Principal。 */
  public Object getPrincipal() {
    Subject subject = SecurityUtils.getSubject();
    if (subject != null) {
      return subject.getPrincipal();
    }

    return null;
  }

  /* 获取当前用户属性。 */
  public Object getPrincipalProperty(String property) {
    Subject subject = SecurityUtils.getSubject();
    Object value = null;

    if (subject != null) {
      Object principal = subject.getPrincipal();

      try {
        BeanInfo bi = Introspector.getBeanInfo(principal.getClass());

        boolean foundProperty = false;
        for (PropertyDescriptor pd : bi.getPropertyDescriptors()) {
          if (pd.getName().equals(property)) {
            value = pd.getReadMethod().invoke(principal, (Object[]) null);
            foundProperty = true;
            break;
          }
        }

        if (!foundProperty) {
          final String message = "Property [" + property + "] not found in principal of type [" + principal.getClass().getName() + "]";
          LOG.trace(message);
        }
      } catch (Exception e) {
        final String message = "Error reading property [" + property + "] from principal of type [" + principal.getClass().getName() + "]";
        LOG.trace(message);
      }
    }

    return value;
  }

  /* 验证当前用户是否属于该角色 。 */
  public boolean hasRole(String role) {
    Subject subject = SecurityUtils.getSubject();
    return subject != null && subject.hasRole(role);
  }

  /* 验证当前用户是否不属于该角色，与 hasRole 逻辑相反。 */
  public boolean lacksRole(String role) {
    return !hasRole(role);
  }

  /* 验证当前用户是否属于以下任意一个角色。 */
  public boolean hasAnyRoles(String roleNames) {
    Subject subject = SecurityUtils.getSubject();
    if (subject != null) {
      for (String role : split(roleNames)) {
        if (subject.hasRole(role.trim())) {
          return true;
        }
      }
    }

    return false;
  }

  /* 验证当前用户是否属于以下任意一个角色。 */
  public boolean hasAnyRoles(Collection<String> roleNames) {
    Subject subject = SecurityUtils.getSubject();

    if (subject != null && roleNames != null) {
      for (String role : roleNames) {
        if (role != null && subject.hasRole(role.trim())) {
          return true;
        }
      }
    }

    return false;
  }

  /* 验证当前用户是否属于以下任意一个角色。 */
  public boolean hasAnyRoles(String[] roleNames) {
    Subject subject = SecurityUtils.getSubject();

    if (subject != null && roleNames != null) {
      for (String role : roleNames) {
        if (role != null && subject.hasRole(role.trim())) {
          return true;
        }
      }
    }

    return false;
  }

  /* 验证当前用户是否拥有指定权限 */
  public boolean hasPermission(String permission) {
    Subject subject = SecurityUtils.getSubject();
    return subject != null && subject.isPermitted(permission);
  }

  /* 验证当前用户是否不拥有指定权限，与 hasPermission 逻辑相反。 */
  public boolean lacksPermission(String permission) {
    return !hasPermission(permission);
  }

  /* 验证当前用户是否拥有以下任意一个权限。 */
  public boolean hasAnyPermissions(String permissions) {
    Subject subject = SecurityUtils.getSubject();
    if (subject != null) {
      for (String permission : split(permissions)) {
        if (permission != null && subject.isPermitted(permission.trim())) {
          return true;
        }
      }
    }

    return false;
  }

  /* 验证当前用户是否拥有以下任意一个权限。 */
  public boolean hasAnyPermissions(Collection<String> permissions) {
    Subject subject = SecurityUtils.getSubject();

    if (subject != null && permissions != null) {
      for (String permission : permissions) {
        if (permission != null && subject.isPermitted(permission.trim())) {
          return true;
        }
      }
    }

    return false;
  }

  /* 验证当前用户是否拥有以下任意一个权限。 */
  public boolean hasAnyPermissions(String[] permissions) {
    Subject subject = SecurityUtils.getSubject();

    if (subject != null && permissions != null) {
      for (String permission : permissions) {
        if (permission != null && subject.isPermitted(permission.trim())) {
          return true;
        }
      }
    }
    return false;
  }

  private String[] split(String val) {
    return val.split("[,\\s]+");
  }
}
