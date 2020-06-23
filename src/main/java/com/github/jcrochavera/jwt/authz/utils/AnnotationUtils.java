package com.github.jcrochavera.jwt.authz.utils;

import java.lang.annotation.Annotation;

/**
 * Created by julio.rocha on 21/6/19.
 *
 * @author julio.rocha
 * @since 1.0.0
 */
public class AnnotationUtils {
    private final Annotation[] annotations;

    public AnnotationUtils(Annotation[] annotations) {
        this.annotations = annotations;
    }

    public boolean isAnnotationPresent(final Class<? extends Annotation> annotationType) {
        for (final Annotation ma : annotations) {
            if (ma.annotationType() == annotationType) {
                return true;
            }
        }
        return false;
    }

    public <T extends Annotation> T getAnnotation(final Class<T> annotationType) {
        for (final Annotation ma : annotations) {
            if (ma.annotationType() == annotationType) {
                return annotationType.cast(ma);
            }
        }
        return null;
    }
}
