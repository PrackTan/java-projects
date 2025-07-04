package com.devteria.identityservice.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

public class DobValidator implements ConstraintValidator<Dobconstraint, LocalDate> {
    private String format;
    private int minAge;
    private int maxAge;
    @Override
    public void initialize(Dobconstraint constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
        this.format = constraintAnnotation.format();
        this.minAge = constraintAnnotation.minAge();
        this.maxAge = constraintAnnotation.maxAge();
    }

    @Override
    public boolean isValid(LocalDate dob, ConstraintValidatorContext context) {
        if(Objects.isNull(dob)){
            return true;
        }
        long age = ChronoUnit.YEARS.between(dob, LocalDate.now());
        
        if(age < minAge || age > maxAge){  
            return false;
        }
        return true;
    }
}