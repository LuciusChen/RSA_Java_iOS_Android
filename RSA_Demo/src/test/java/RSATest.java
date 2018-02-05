import Util.RSAUtils;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

public class RSATest {

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;

    public String getData()
    {
        List<Person> personList = new ArrayList<>();
        int testMaxCount = 10;//测试的最大数据条数
        //添加测试数据
        for (int i = 0; i < testMaxCount; i++ )
        {
            Person person = new Person();
            person.setAge(i);
            person.setName("name->" + String.valueOf(i));
            personList.add(person);
        }
        // 生成自己想要测试的数据
        String jsonData = personList.toString();

        System.out.println("加密前数据===== 1 =====>" + jsonData);
        return jsonData;
    }

    public void getkey()
    {
        // 随机生成RSA密钥对
        KeyPair keyPair = RSAUtils.generateRSAKeyPair(RSAUtils.DEFAULT_KEY_SIZE);
        // 公钥
        if (keyPair != null)
        {
            publicKey = (RSAPublicKey)keyPair.getPublic();
            System.out.println(
                    "publicKey---->" + (new BASE64Encoder()).encodeBuffer(publicKey.getEncoded()));
            // 私钥
            privateKey = (RSAPrivateKey)keyPair.getPrivate();
            System.out.println(
                    "privateKey---->" + (new BASE64Encoder()).encodeBuffer(privateKey.getEncoded()));
        }
        try
        {
            // 得到公钥字符串
            String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
            // 得到私钥字符串
            String privateKeyString = Base64.encodeBase64String(privateKey.getEncoded());
            // 将密钥对写入到文件
            FileWriter pubfw = new FileWriter("/Users/rabbit/publicKey.keystore");
            FileWriter prifw = new FileWriter("/Users/rabbit/privateKey.keystore");
            BufferedWriter pubbw = new BufferedWriter(pubfw);
            BufferedWriter pribw = new BufferedWriter(prifw);
            pubbw.write(publicKeyString);
            pribw.write(privateKeyString);
            pubbw.flush();
            pubbw.close();
            pubfw.close();
            pribw.flush();
            pribw.close();
            prifw.close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void RSA_demo(){
        // 得到随机的密钥对儿
        //getkey();
        // 待加密的数据
        String data = getData();

        try
        {
            publicKey = RSAUtils.loadPublicKeyByStr(
                    RSAUtils.loadKeyByFile("/Users/rabbit/publicKey.keystore"));
            System.out.println("公钥========>" + publicKey);
            privateKey = RSAUtils.loadPrivateKeyByStr(
                    RSAUtils.loadKeyByFile("/Users/rabbit/privateKey.keystore"));
            System.out.println("私钥========>" + publicKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        // 加密后的数据串（String型）
        String encryStr = "";
        // 解密后数据串（String型）
        String decryStr = "";
        // 加密后的数据（byte[]型的）
        byte[] encryptBytes;
        // 解密后数据（byte[]型的）
        byte[] decryptBytes;

        /**
         * 对数据进行：公钥加密，私钥解密
         */
        try
        {
            //公钥加密
            encryptBytes = RSAUtils.encrypt(data, publicKey);
            encryStr = new String(encryptBytes);
            System.out.println("加密后数据===== 2 =====>" + encryStr);
            //私钥解密
            decryptBytes = RSAUtils.decrypt(encryStr, privateKey);
            decryStr = new String(decryptBytes);
            System.out.println("解密后数据===== 3 =====>" + decryStr);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        try
        {

            System.out.println("签名前数据===== 4 =====>" + data);
            String sign = RSAUtils.sign(data.getBytes(), privateKey);
            System.out.println("签名后数据===== 5 =====>" + sign);
            boolean status = RSAUtils.verify(data.getBytes(), publicKey, sign);
            System.out.println("验签结果===== 6 =====>" + status);

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
