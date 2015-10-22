package com.github.shiro.support;

import com.google.common.base.Objects;

import java.io.Serializable;

/**
 * 自定义Authentication对象，使得Subject除了携带用户的登录名外还可以携带更多信息.
 */
public class ShiroUser implements Serializable {
  private static final long serialVersionUID = -1373760761780840081L;
  private final String username;

  public ShiroUser(String username) {
    this.username = username;
  }

  public String getUsername() {
    return username;
  }

  /**
   * 本函数输出将作为默认的<shiro:principal/>输出.
   */
  @Override
  public String toString() {
    return username;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ShiroUser shiroUser = (ShiroUser) o;
    return Objects.equal(username, shiroUser.username);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(username);
  }
}
