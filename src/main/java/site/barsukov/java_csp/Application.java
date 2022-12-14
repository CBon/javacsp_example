package site.barsukov.java_csp;

import org.cryptacular.util.CertUtil;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.reprov.RevCheck;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Application {
  public static void main(String[] args) {
    try {
      System.out.println("CryptoPro start initialization");
      System.setProperty("file.encoding", "UTF-8");
      Security.addProvider(new JCSP()); // провайдер JCSP
      Security.addProvider(new RevCheck()); // провайдер проверки сертификатов JCPRevCheck
      // (revocation-провайдер)
      Security.addProvider(new CryptoProvider()); // провайдер шифрования JCryptoP
      System.out.println("CryptoPro initialized");

    } catch (Exception e) {
      System.err.println("Exception in initializing crypto pro : " + e);
    }

    try {
      KeyStore ks = KeyStore.getInstance("REGISTRY", "JCSP");
      ks.load(null, null);
      Enumeration<String> aliases = ks.aliases();

      while (aliases.hasMoreElements()) {
        Certificate cert = ks.getCertificate(aliases.nextElement());
        if (cert instanceof X509Certificate curCert) {
          System.out.println(CertUtil.subjectCN(curCert));
        }
      }
    } catch (KeyStoreException e) {
      System.err.println("Error: " + e);
    } catch (IOException
        | CertificateException
        | NoSuchAlgorithmException
        | NoSuchProviderException e) {
      e.printStackTrace();
    }
  }
}
