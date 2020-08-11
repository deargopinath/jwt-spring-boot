package com.gopinath.token.issuer.service;

import com.gopinath.token.issuer.model.RequestData;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.cert.X509Certificate;
import com.nimbusds.jose.util.X509CertUtils;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Enumeration;
//
@Service
public class TokenService {

    private final Logger LOG = LoggerFactory.getLogger(TokenService.class);
    
    @Value("${token.issuer.url}")
    private String issuer;
    
    @Value("${token.issuer.pkcs12}")
    private String serverPKCS;
    
    @Value("${service.provider.x509}")
    private String clientCertificate;

    private RSAKey getPublicKey(String certificateFile) {
        RSAKey publicKey = null;
        try {
            String fileContent = new String(Files.readAllBytes(Paths.get(certificateFile)));
            X509Certificate certificate = X509CertUtils.parse(fileContent);
            publicKey = RSAKey.parse(certificate);
            LOG.info("Public key was fetched from the certificate");
        } catch (IOException | JOSEException e) {
            LOG.error(e.toString());
        }
        return publicKey;
    }
    
    private RSAKey getJSONWebKey(String pkcsFile) {
        RSAKey jwk = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream pkcs = new FileInputStream(pkcsFile);
            keyStore.load(pkcs, "".toCharArray());
            Enumeration aliases = keyStore.aliases();
            while(aliases.hasMoreElements()){
                String alias = (String)aliases.nextElement();
                RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(alias,"".toCharArray());
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                RSAKey publicKey = RSAKey.parse(certificate);
                jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
                break;
            }
        } catch (IOException 
                | KeyStoreException 
                | JOSEException 
                | NoSuchAlgorithmException 
                | UnrecoverableKeyException 
                | CertificateException ex) {
            LOG.error(ex.toString());
        }
        return jwk;
    }
    
    public String getToken(RequestData requestData) {
        String token = "unknown";
        try {
            
            String subject = requestData.getSubject();
            String user = requestData.getUser();
            String account = requestData.getAccount();
            LOG.info("user = " + user + ", account = " + account + ", subject = " + subject);

            RSAKey serverJWK = getJSONWebKey(serverPKCS);
            
            JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(serverJWK).build();
            Calendar now = Calendar.getInstance();
            Date issueTime = now.getTime();
            now.add(Calendar.MINUTE, 10);
            Date expiryTime = now.getTime();
            String jti = String.valueOf(issueTime.getTime());
            
           // Date expiryTime = issueTime.
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .issueTime(issueTime)
                    .expirationTime(expiryTime)
                    .claim("user", user)
                    .claim("account", account)
                    .jwtID(jti)
                    .build();
            LOG.info("JWT claims = " + jwtClaims.toString());
            SignedJWT jws = new SignedJWT(jwtHeader, jwtClaims);
            RSASSASigner signer = new RSASSASigner(serverJWK);
            jws.sign(signer);
                        
             JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, 
                     EncryptionMethod.A256GCM).contentType("JWT").build();
            
            JWEObject jwe = new JWEObject(jweHeader, new Payload(jws));
            
            // Encrypt with the recipient's public key
            RSAKey clientPublicKey = getPublicKey(clientCertificate);

            jwe.encrypt(new RSAEncrypter(clientPublicKey));

            token = jwe.serialize();
            LOG.info("Token = " + token);
            
        } catch (final JOSEException e) {
            // TODO Auto-generated catch block
            LOG.error(e.toString());
        }
        return token;
    }
}
