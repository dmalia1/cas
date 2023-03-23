package org.apereo.cas.impl.engine;


import org.apereo.cas.api.AuthenticationRequestRiskCalculator;
import org.apereo.cas.api.AuthenticationRiskEvaluator;
import org.apereo.cas.api.AuthenticationRiskScore;
import org.apereo.cas.audit.AuditActionResolvers;
import org.apereo.cas.audit.AuditResourceResolvers;
import org.apereo.cas.audit.AuditableActions;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.support.events.CasEventRepository;
import org.apereo.cas.support.events.dao.CasEvent;
import org.apereo.cas.support.events.ticket.CasTicketGrantingTicketCreatedEvent;
import org.apereo.cas.util.spring.beans.BeanSupplier;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.inspektr.audit.annotation.Audit;

import jakarta.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This is {@link DefaultAuthenticationRiskEvaluator}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Slf4j
@Getter
@RequiredArgsConstructor
public class DefaultAuthenticationRiskEvaluator implements AuthenticationRiskEvaluator {
    private final List<AuthenticationRequestRiskCalculator> calculators;

    /**
     * CAS event repository instance.
     */
    private final CasEventRepository casEventRepository;

    /**
     * CAS settings.
     */
    private final CasConfigurationProperties casProperties;

    private final boolean cacheResults;

    @Audit(action = AuditableActions.EVALUATE_RISKY_AUTHENTICATION,
        actionResolverName = AuditActionResolvers.ADAPTIVE_RISKY_AUTHENTICATION_ACTION_RESOLVER,
        resourceResolverName = AuditResourceResolvers.ADAPTIVE_RISKY_AUTHENTICATION_RESOURCE_RESOLVER)
    @Override
    public AuthenticationRiskScore eval(final Authentication authentication,
                                        final RegisteredService service,
                                        final HttpServletRequest request) {

        val activeCalculators = this.calculators
            .stream()
            .filter(BeanSupplier::isNotProxy).toList();

        if (activeCalculators.isEmpty()) {
            return new AuthenticationRiskScore(AuthenticationRequestRiskCalculator.HIGHEST_RISK_SCORE);
        }
        val principal = authentication.getPrincipal();
        val events = buildSupplier(principal);
        val scores = activeCalculators
            .stream()
            .map(r -> r.calculate(authentication, service, request, events))
            .filter(Objects::nonNull).toList();

        val sum = scores.stream()
            .map(AuthenticationRiskScore::score)
            .filter(Objects::nonNull)
            .reduce(BigDecimal.ZERO, BigDecimal::add);
        val score = sum.divide(BigDecimal.valueOf(activeCalculators.size()), 2, RoundingMode.UP);
        return new AuthenticationRiskScore(score);
    }

    private Supplier<Stream<? extends CasEvent>> buildSupplier(final Principal principal){
        return new Supplier<Stream<? extends CasEvent>>() {
            private List<? extends CasEvent> list;

            @Override
            public Stream<? extends CasEvent> get() {
                if (list == null && cacheResults){
                    list = getCasTicketGrantingTicketCreatedEventsFor(principal.getId()).collect(Collectors.toList());
                }
                if (list != null && cacheResults){
                    return list.stream();
                }
                return getCasTicketGrantingTicketCreatedEventsFor(principal.getId());
            }
        };
    }

    /**
     * Gets cas ticket granting ticket created events.
     *
     * @param principal the principal
     * @return the cas ticket granting ticket created events for
     */
    protected Stream<? extends CasEvent> getCasTicketGrantingTicketCreatedEventsFor(final String principal) {
        val type = CasTicketGrantingTicketCreatedEvent.class.getName();
        LOGGER.debug("Retrieving events of type [{}] for [{}]", type, principal);

        val date = ZonedDateTime.now(ZoneOffset.UTC)
                .minusDays(casProperties.getAuthn().getAdaptive().getRisk().getCore().getDaysInRecentHistory());
        return casEventRepository.getEventsOfTypeForPrincipal(type, principal, date);
    }
}
