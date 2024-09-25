package lissa.trading.auth.service.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Aspect
public class LogEndpointAspect {

    @Before("execution(public * lissa.trading.auth.service.controller..*Controller*.*(..))")
    public void logBeforeControllerMethod(JoinPoint joinPoint) {
        AuthenticationContextHolder.UserInfo userInfo = AuthenticationContextHolder.getUserInfo();
        log.info("Method {} invoked by user with externalId {} and telegram nickname {}. Arguments: {}",
                joinPoint.getSignature().toShortString(),
                userInfo.getExternalId(),
                userInfo.getTelegramNickname(),
                joinPoint.getArgs());
    }

    @AfterReturning(pointcut = "execution(public * lissa.trading.auth.service.controller..*Controller*.*(..))", returning = "result")
    public void logAfterReturning(JoinPoint joinPoint, Object result) {
        AuthenticationContextHolder.UserInfo userInfo = AuthenticationContextHolder.getUserInfo();
        log.info("Method {} successfully executed by user with externalId {} and telegram nickname {}. Result: {}",
                joinPoint.getSignature().toShortString(),
                userInfo.getExternalId(),
                userInfo.getTelegramNickname(),
                result);
    }

    @AfterThrowing(pointcut = "execution(public * lissa.trading.auth.service.controller..*Controller*.*(..))", throwing = "exception")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable exception) {
        AuthenticationContextHolder.UserInfo userInfo = AuthenticationContextHolder.getUserInfo();
        String methodName = joinPoint.getSignature().toShortString();

        if (exception instanceof AccessDeniedException) {
            log.error("Access Denied for user with externalId {} and telegram nickname {} in method {}: {}",
                    userInfo.getExternalId(),
                    userInfo.getTelegramNickname(),
                    methodName,
                    exception.getMessage());
        } else {
            log.error("Exception in method {} for user with externalId {} and telegram nickname {}: {}",
                    methodName,
                    userInfo.getExternalId(),
                    userInfo.getTelegramNickname(),
                    exception.getMessage(),
                    exception);
        }
    }
}