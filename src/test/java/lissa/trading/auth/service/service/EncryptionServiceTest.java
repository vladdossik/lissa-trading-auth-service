package lissa.trading.auth.service.service;

import lissa.trading.auth.service.exception.EncryptionTokenException;
import lissa.trading.auth.service.service.user.EncryptionService;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;

import java.lang.reflect.InvocationTargetException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncryptionServiceTest extends BaseTest {

    @InjectMocks
    private EncryptionService encryptionService;

    private final String secretKeyString = createSecretKeyString(32);

    @Test
    void testEncryptAndDecrypt() throws Exception {
        setField(encryptionService, secretKeyString);
        invokePrivateMethod(encryptionService);

        String plainText = "Hello World";

        String cipherText = encryptionService.encrypt(plainText);
        assertEquals(plainText, encryptionService.decrypt(cipherText));

        String anotherCipherText = encryptionService.encrypt(plainText);
        assertEquals(plainText, encryptionService.decrypt(anotherCipherText));

        assertNotEquals(cipherText, anotherCipherText);
    }

    @Test
    void testDecryptInvalidCipherText() throws Exception {
        setField(encryptionService, secretKeyString);
        invokePrivateMethod(encryptionService);

        String invalidCipherText = "InvalidCipherText";
        assertThrows(EncryptionTokenException.class, () -> {
            encryptionService.decrypt(invalidCipherText);
        });
    }

    @Test
    void testEncryptDecryptWithInvalidKeyLength() {
        String invalidKey = createSecretKeyString(16);
        setField(encryptionService, invalidKey);

        assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(encryptionService));
    }
}