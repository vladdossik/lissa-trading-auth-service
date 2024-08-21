package lissa.trading.auth.service.service;

public interface EncryptionService {
    String encrypt(String plainText);

    String decrypt(String cipherText);
}
