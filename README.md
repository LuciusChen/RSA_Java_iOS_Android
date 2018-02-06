# RSA_Java_iOS_Android

iOS, Android 和 Java 对接 RSA 加密解密及签名验签

遇到的问题：

- iOS 与 Java 分段加密实现原理不一致，统一加密原理。
- iOS 与 Java 签名实现不一致，iOS 要采用 OpenSSL 的签名和验证方法（仿照 [iOSRSAHandler](https://github.com/HustBroventure/iOSRSAHandler) 中的 HBRSAHandler.m 实现即可）。
- Android 的 JDK 与 Java 的 JDK 实现不一致，需要将下面代码（Java）中的 `RSA` 替换成 `RSA/ECB/PKCS1Padding` 或者 `RSA/None/NoPadding`。
    
    ```
    Cipher cipher = Cipher.getInstance("RSA");
    ```


