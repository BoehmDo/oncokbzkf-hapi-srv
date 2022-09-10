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
      String[] credentials = new String[2];

      if (authHeader != null && authHeader.toLowerCase().startsWith("basic")) {
         // Authorization: Basic base64credentials
         String base64Credentials = authHeader.substring("Basic".length()).trim();
         byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
         String strCred = new String(credDecoded, StandardCharsets.UTF_8);
         // credentials = username:password
         credentials = strCred.split(":", 2);
      }

      /*
       * Get valid usernames and passwords for write access from environment variable
       */
      Map<String, String> writeUserMap = new HashMap<String, String>();
      Map<String, String> readUserMap = new HashMap<String, String>();
      Path writeCredPath = Paths.get("/config/writecredentials.json");
      Path readCredPath = Paths.get("/config/readcredentials.json");
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

      if (!writeUserMap.isEmpty() && checkCredentials(writeUserMap, credentials)) {
         // This user has access to everything
         writeAuthorized = true;
         readAuthorized = true;

      } else if (!readUserMap.isEmpty() && checkCredentials(readUserMap, credentials)) {
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

   private boolean checkCredentials(Map<String, String> validUserMap, String[] credentials) {
      if (validUserMap.containsKey(credentials[0]) && validUserMap.get(credentials[0]).equals(credentials[1])) {
         return true;
      } else {
         return false;
      }
   }
}
