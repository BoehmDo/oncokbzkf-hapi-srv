package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

import java.util.List;

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
      String userId = null;
      boolean userIsAdmin = false;
      String authHeader = theRequestDetails.getHeader("Authorization");
      String[] values = new String[2];
      if (authHeader != null && authHeader.toLowerCase().startsWith("basic")) {
         // Authorization: Basic base64credentials
         String base64Credentials = authHeader.substring("Basic".length()).trim();
         byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
         String credentials = new String(credDecoded, StandardCharsets.UTF_8);
         // credentials = username:password
         values = credentials.split(":", 2);
      }

      if ("user".equals(values[0]) && "password".equals(values[1])) {
         // This user has access only to Patient/1 resources
         userId = values[0];
      } else if ("admin".equals(values[0]) && "adminpassword".equals(values[1])) {
         // This user has access to everything
         userId = values[0];
         userIsAdmin = true;
      }

      // If the user is a specific patient, we create the following rule chain:
      // Allow the user to read anything in their own patient compartment
      // Allow the user to write anything in their own patient compartment
      // If a client request doesn't pass either of the above, deny it
      
      System.out.println("AccessBy: "+values[0] + " " + values[1]+ " authHeader: "+authHeader);

      if (userId == null || !userIsAdmin) {
         
         return new RuleBuilder()
            .allow().read().allResources().withAnyId().andThen()
            .denyAll("UserButNoAdmin")
            .build();
      }

      // If the user is an admin, allow everything
      if (userIsAdmin) {
         return new RuleBuilder()
            .allowAll()
            .build();
      }

      // By default, deny everything. This should never get hit, but it's
      // good to be defensive
      return new RuleBuilder()
         .denyAll()
         .build();
   }
}
 