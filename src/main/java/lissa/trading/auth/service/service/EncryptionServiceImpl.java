package lissa.trading.auth.service.service;

import lissa.trading.auth.service.exception.EncryptionTokenException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    private final SecretKey secretKey;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    public EncryptionServiceImpl() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        this.secretKey = keyGen.generateKey();
    }

    @Override
    public String encrypt(String plainText) throws EncryptionTokenException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes());
            byte[] ivAndCipherText = ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();
            return Base64.getEncoder().encodeToString(ivAndCipherText);
        } catch (Exception e) {
            throw new EncryptionTokenException("Ошибка шифрования", e);
        }
    }

    @Override
    public String decrypt(String cipherText) throws EncryptionTokenException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] ivAndCipherText = Base64.getDecoder().decode(cipherText);
            ByteBuffer byteBuffer = ByteBuffer.wrap(ivAndCipherText);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            byteBuffer.get(iv);
            byte[] cipherTextBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherTextBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] plainText = cipher.doFinal(cipherTextBytes);
            return new String(plainText);
        } catch (Exception e) {
            throw new EncryptionTokenException("Ошибка дешифрования", e);
        }
    }
}
