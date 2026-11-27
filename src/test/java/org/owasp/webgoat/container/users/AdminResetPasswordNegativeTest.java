/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.WebGoat;
import org.owasp.webgoat.container.i18n.Language;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Negative security tests for {@code POST /service/admin/users/{username}/reset-password}.
 *
 * <p>Unlike {@link AdminControllerTest} (standalone MockMvc, no security), these tests run against
 * the real Spring Security filter chain and method security, so each one fails if the control it
 * covers is removed:
 *
 * <ul>
 *   <li>Authentication – anonymous callers are rejected with 401.
 *   <li>Authorization – an authenticated {@code WEBGOAT_USER} is rejected with 403.
 *   <li>Input validation – usernames outside the allow-list are rejected with 400.
 *   <li>Error handling – backend failures return a controlled response without internal details.
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class AdminResetPasswordNegativeTest {

  private static final String ENDPOINT = "/service/admin/users/{username}/reset-password";
  private static final String TARGET_USER = "victim-user";

  @Autowired private WebApplicationContext wac;
  @MockitoSpyBean private UserService userService;
  @MockitoBean private Language language;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    when(language.getLocale()).thenReturn(Locale.getDefault());
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  /** Authentication: without a session the request is rejected and no password is reset. */
  @Test
  void anonymousRequestIsRejectedWith401() throws Exception {
    mockMvc
        .perform(post(ENDPOINT, TARGET_USER).header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Authorization: a regular user cannot reset another user's password. */
  @Test
  void regularUserIsForbidden() throws Exception {
    mockMvc
        .perform(post(ENDPOINT, TARGET_USER).with(user("student").authorities(() -> "WEBGOAT_USER")))
        .andExpect(status().isForbidden());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Input validation: a username outside the allow-list never reaches the service layer. */
  @Test
  void maliciousUsernameIsRejectedWith400() throws Exception {
    mockMvc
        .perform(
            post(ENDPOINT, "x' OR '1'='1")
                .with(user("webgoat-admin").authorities(() -> "WEBGOAT_ADMIN")))
        .andExpect(status().isBadRequest());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  /** Error handling: an internal failure is turned into a controlled response with no details. */
  @Test
  void backendFailureDoesNotLeakInternalDetails() throws Exception {
    doThrow(new IllegalStateException("jdbc:hsqldb:file:/internal/db connection refused"))
        .when(userService)
        .resetPassword(eq(TARGET_USER), anyString());

    mockMvc
        .perform(
            post(ENDPOINT, TARGET_USER)
                .with(user("webgoat-admin").authorities(() -> "WEBGOAT_ADMIN")))
        .andExpect(status().isNotFound())
        .andExpect(content().string(not(containsString("jdbc"))))
        .andExpect(content().string(not(containsString("temporaryPassword"))));
  }
}
