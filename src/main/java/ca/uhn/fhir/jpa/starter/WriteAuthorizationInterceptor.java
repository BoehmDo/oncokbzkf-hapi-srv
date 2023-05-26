package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;

import java.util.Base64;
import java.util.HashMap;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.List;
import java.io.IOException;
import java.lang.reflect.Type;

import com.google.gson.Gson;
import com.google.gson.reflect.*;

import org.apache.commons.codec.digest.MessageDigestAlgorithms.*;

@SuppressWarnings("ConstantConditions")
public class WriteAuthorizationInterceptor extends AuthorizationInterceptor {

   @Override
   public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

      // Process authorization header - The following is a fake
      // implementation. Obviously we'd want something more real
      // for a production scenario.
      //
      // In this basic example we have two hardcoded bearer tokens,
      // one which is for a user that has access to one patient, and
      // another that has full access.
      boolean writeAuthorized = false;
      boolean readAuthorized = false;
      String authHeader = theRequestDetails.getHeader("Authorization");
      String password = "";
      String user = "";

      if (authHeader != null && authHeader.toLowerCase().startsWith("basic")) {
         // Authorization: Basic base64credentials
         String base64Credentials = authHeader.substring("Basic".length()).trim();
         byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
         String strCred = new String(credDecoded, StandardCharsets.UTF_8);
         // credentials = username:password
         String[] credentials = strCred.split(":", 2);
         user = credentials[0];
         password = credentials[1];
      }

      /*
       * Get valid usernames and passwords for write access from config files
       */
      Map<String, String> writeUserMap = new HashMap<String, String>();
      Map<String, String> readUserMap = new HashMap<String, String>();
      Path writeCredPath = Paths.get("config/writecredentials.json");
      Path readCredPath = Paths.get("config/readcredentials.json");
      String writeCredFileString = null;
      String readCredFileString = null;
      try {
         writeCredFileString = Files.readString(writeCredPath, StandardCharsets.US_ASCII);
      } catch (IOException ioe) {
         ioe.printStackTrace();
      }
      try {
         readCredFileString = Files.readString(readCredPath, StandardCharsets.US_ASCII);
      } catch (IOException ioe) {
         ioe.printStackTrace();
      }

      Type collectionType = new TypeToken<Map<String, String>>() {
      }.getType();
      Gson gson = new Gson();
      if (writeCredFileString != null) {
         writeUserMap = gson.fromJson(writeCredFileString, collectionType);
      }
      if (readCredFileString != null) {
         readUserMap = gson.fromJson(readCredFileString, collectionType);
      }

      if (!writeUserMap.isEmpty() && checkCredentials(writeUserMap, user, password)) {
         // This user has access to everything
         writeAuthorized = true;
         readAuthorized = true;

      } else if (!readUserMap.isEmpty() && checkCredentials(readUserMap, user, password)) {
         readAuthorized = true;
      }

      if (!writeAuthorized && readAuthorized) {

         return new RuleBuilder()
               .allow().read().allResources().withAnyId().andThen()
               .denyAll("NoWriteAccessWithoutValidCredentials")
               .build();
      }

      // If the user is an admin, allow everything
      if (writeAuthorized && readAuthorized) {
         return new RuleBuilder()
               .allowAll()
               .build();
      }

      // By default deny everything
      return new RuleBuilder()
            .denyAll("NoAccessWithoutValidBasicAuth")
            .build();
   }

   private boolean checkCredentials(Map<String, String> validUserMap, String user, String password) {
      if (!validUserMap.containsKey(user)) {
         return false;
      } 

      String PW_Hash = org.apache.commons.codec.digest.DigestUtils.sha256(password).toString();
      return PW_Hash == validUserMap.get(user);
   }
}
