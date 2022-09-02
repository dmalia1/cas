package org.apereo.cas.notifications.sms;

import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.function.FunctionUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.With;
import lombok.experimental.SuperBuilder;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;

/**
 * This is {@link SmsRequest}.
 *
 * @author Misagh Moayyed
 * @since 6.6.0
 */
@SuperBuilder
@Getter
@With
@RequiredArgsConstructor
public class SmsRequest {
    private final Principal principal;

    private final String attribute;

    private final String text;

    private final String from;

    private final String to;

    public boolean hasAttributeValue() {
        return StringUtils.isNotBlank(attribute) && principal.getAttributes().containsKey(attribute);
    }

    public Optional<Object> getAttributeValue() {
        val value = principal.getAttributes().get(attribute);
        return CollectionUtils.firstElement(value);
    }

    public String getRecipient() {
        return FunctionUtils.doIf(hasAttributeValue(),
            () -> getAttributeValue().map(Object::toString).orElseGet(this::getTo),
            this::getTo).get();
    }
}
