package com.devteria.identityservice.validator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = DobValidator.class)
public @interface Dobconstraint {
    String message() default "Invalid date of birth"; //message to be displayed if the date of birth is invalid
    String format() default "dd/MM/yyyy"; //format of the date of birth
    int minAge() default 18; //minimum age to be used for validation
    int maxAge() default 100; //maximum age to be used for validation
    Class<?>[] groups() default {}; //groups to be used for validation
    Class<? extends Payload>[] payload() default {}; //payload to be used for validation
}