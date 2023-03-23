package org.apereo.cas.impl.calcs;

import lombok.Getter;
import org.apereo.cas.api.AuthenticationRequestRiskCalculator;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.impl.engine.DefaultAuthenticationRiskEvaluator;
import org.apereo.cas.services.RegisteredServiceTestUtils;

import lombok.val;
import org.apereo.cas.support.events.CasEventRepository;
import org.apereo.cas.support.events.dao.CasEvent;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link DateTimeAuthenticationRequestRiskCalculatorTests}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@TestPropertySource(properties = {"cas.authn.adaptive.risk.date-time.enabled=true", "cas.authn.adaptive.risk.date-time.window-in-hours=4"})
@Tag("Authentication")
public class DateTimeAuthenticationRequestRiskCalculatorTests extends BaseAuthenticationRequestRiskCalculatorTests {


    @Test
    public void verifyTestWhenNoAuthnEventsFoundForUser() {
        val authentication = CoreAuthenticationTestUtils.getAuthentication("datetimeperson");
        val service = RegisteredServiceTestUtils.getRegisteredService("test");
        val request = new MockHttpServletRequest();
        val score = authenticationRiskEvaluator.eval(authentication, service, request);
        assertTrue(score.isHighestRisk());
    }

    @Test
    public void verifyTestWhenAuthnEventsFoundForUser() {
        val authentication = CoreAuthenticationTestUtils.getAuthentication("casuser");
        val service = RegisteredServiceTestUtils.getRegisteredService("test");
        val request = new MockHttpServletRequest();
        val score = authenticationRiskEvaluator.eval(authentication, service, request);
        assertTrue(score.isLowestRisk());
    }

    @Test
    public void verifyTestWhenAuthnEventsFoundForUserAndVerifyCachingIsUsed() {
        val authentication = CoreAuthenticationTestUtils.getAuthentication("casuser");
        val service = RegisteredServiceTestUtils.getRegisteredService("test");
        val request = new MockHttpServletRequest();
        val calculator = new DateTimeAuthenticationRequestRiskCalculator(casEventRepository, casProperties);
        val calculatorList = new ArrayList<AuthenticationRequestRiskCalculator>();
        calculatorList.add(calculator);

        casProperties.getAuthn().getAdaptive().getRisk().getCore().setCacheEventStreamPerRequest(true);
        val privateAuthenticationRiskEvaluator = new TestAuthenticationRiskEvaluator(calculatorList, casEventRepository, casProperties, true);
        val score = privateAuthenticationRiskEvaluator.eval(authentication, service, request);
        assertTrue(score.isLowestRisk());
        assertEquals(-1, privateAuthenticationRiskEvaluator.numberOfTimesCalled);
    }
    @Getter
    private class TestAuthenticationRiskEvaluator extends DefaultAuthenticationRiskEvaluator {
         private int numberOfTimesCalled;
         TestAuthenticationRiskEvaluator(final List<AuthenticationRequestRiskCalculator> calculators, final CasEventRepository casEventRepository,
                                               final CasConfigurationProperties casProperties, final boolean cacheResults) {
            super(calculators, casEventRepository, casProperties, cacheResults);
            numberOfTimesCalled = 0;
        }

        @Override
        protected Stream<? extends CasEvent> getCasTicketGrantingTicketCreatedEventsFor(String principal) {
             numberOfTimesCalled++;
            return super.getCasTicketGrantingTicketCreatedEventsFor(principal);
        }
    }
}
