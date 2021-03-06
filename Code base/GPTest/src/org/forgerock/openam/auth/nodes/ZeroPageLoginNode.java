/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2020 ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import static java.util.Collections.singletonMap;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.mail.internet.MimeUtility;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.IdType;

/** A node that checks to see if zero-page login headers have specified username and password for this request. */
@Node.Metadata(outcomeProvider = ZeroPageLoginNode.OutcomeProvider.class,
        configClass = ZeroPageLoginNode.Config.class,
        tags = {"basic authn", "basic authentication"})
public class ZeroPageLoginNode implements Node {

    private static final String TRUE_OUTCOME_ID = "true";
    private static final String FALSE_OUTCOME_ID = "false";
    private static final String REFERER_HEADER_KEY = "referer";

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The name of the HTTP header containing the username.
         * @return the header name.
         */
        @Attribute(order = 100)
        default String usernameHeader() {
            return "X-OpenAM-Username";
        }

        /**
         * The name of the HTTP header containing the password.
         * @return the header name.
         */
        @Attribute(order = 200)
        default String passwordHeader() {
            return "X-OpenAM-Password";
        }

        /**
         * Sets the node to allow requests to authenticate without a referer.
         *
         * @return the allow without referer flag.
         */
        @Attribute(order = 300)
        default boolean allowWithoutReferer() {
            return true;
        }

        /**
         * A white list of allowed referers. If a referer is required, the request must have a referer on this list.
         *
         * @return the referer white list.
         */
        @Attribute(order = 400)
        default Set<String> referrerWhiteList() {
            return new HashSet<>();
        }
    }

    private final Config config;
    private final IdentityUtils identityUtils;
    private final Logger logger = LoggerFactory.getLogger(ZeroPageLoginNode.class);

    /**
     * Create the node.
     * @param config The service config.
     * @param identityUtils The identity utils implementation.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ZeroPageLoginNode(@Assisted Config config, IdentityUtils identityUtils) throws NodeProcessException {
        this.config = config;
        this.identityUtils = identityUtils;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("ZeroPageLoginNode started");
        System.out.println("ZeroPageLoginNode started");
       
        boolean hasBlockID = false;
        // BlockIDAuthn contains encrypted payload returned from BlockID server.
        String BlockIDAuthn = context.request.servletRequest.getParameter("BlockIDAuthn");
        System.out.println("1:" + context.request.servletRequest.getParameterValues("BlockIDAuthn"));
        if(BlockIDAuthn!=null ) {
        	hasBlockID = true;
        }
        
    	System.out.println("hasBlockID:" + hasBlockID );
        Enumeration<String> params =  context.request.servletRequest.getParameterNames(); 
        while(params.hasMoreElements()){
         String paramName = params.nextElement();
         System.out.println("Parameter Name - "+paramName+", Value - "+ context.request.servletRequest.getParameter(paramName));
        }
        
        if(hasBlockID) {
        	
        	System.out.println("Setting username:" + BlockIDAuthn );
        	//context.request.headers.put(config.usernameHeader(), BlockIDAuthn);
        	System.out.println("Username obtained");
        	
        	
        	BlockIDSDK2 sdk = new BlockIDSDK2(null,null,null);
        	String decodedString = new String(Base64.getDecoder().decode(BlockIDAuthn.getBytes()));
        	System.out.println("decodedString:" +decodedString);
        	
        	 String userName = sdk.extractUsername(decodedString);
        	

        	
        	  JsonValue sharedState = context.sharedState.copy();
              JsonValue transientState = context.transientState.copy();
              updateStateIfPresentForBlockID(context, true, config.usernameHeader(), USERNAME, sharedState,userName);
             
              String realm = context.sharedState.get(REALM).asString();
              System.out.println("Setting header");
              return goTo(true)
                      .withUniversalId(identityUtils.getUniversalId(userName, realm, IdType.USER))
                      .replaceSharedState(sharedState).replaceTransientState(transientState).build();
        
        }else {
        boolean hasUsername = context.request.headers.containsKey(config.usernameHeader());
        boolean hasPassword = context.request.headers.containsKey(config.passwordHeader());
        if (!hasUsername && !hasPassword) {
            logger.debug("no username or password set");
            return goTo(false).build();
        }
        boolean hasReferer = context.request.headers.containsKey(REFERER_HEADER_KEY);
        if (!config.allowWithoutReferer()) {
            if (!hasReferer || !isOnWhiteList(context.request.headers.get(REFERER_HEADER_KEY))) {
                return goTo(false).build();
            }
        }
        JsonValue sharedState = context.sharedState.copy();
        JsonValue transientState = context.transientState.copy();
        updateStateIfPresent(context, hasUsername, config.usernameHeader(), USERNAME, sharedState);
        updateStateIfPresent(context, hasPassword, config.passwordHeader(), PASSWORD, transientState);
        logger.debug("username {} and password set in sharedState", config.usernameHeader());
        String userName = context.sharedState.get(USERNAME).asString();
        String realm = context.sharedState.get(REALM).asString();
        return goTo(true)
                .withUniversalId(identityUtils.getUniversalId(userName, realm, IdType.USER))
                .replaceSharedState(sharedState).replaceTransientState(transientState).build();
        }//end else hasblockid
    }
    
    private void updateStateIfPresentForBlockID(TreeContext context, boolean hasValue, String headerName, String stateKey,
            JsonValue state, String BlockIDAuthn) throws NodeProcessException {
        if (hasValue) {
        	System.out.println("inside updateStateIfPresent");
            List<String> values = context.request.headers.get(headerName);
            System.out.println(headerName+ ":" + values);
			/*
			 * if (values.size() != 1) { System.out.
			 * println("expecting only one header value for username and/or password but size is {}"
			 * + values.size()); logger.
			 * error("expecting only one header value for username and/or password but size is {}"
			 * , values.size()); throw new
			 * NodeProcessException("Expecting only one header value for username and/or password "
			 * + "but size is" + values.size()); }
			 */            String value = BlockIDAuthn;
            System.out.println(stateKey+ ":" + value);
            try {
                if (StringUtils.isNotEmpty(value)) {
                    value = MimeUtility.decodeText(value);
                }
            } catch (UnsupportedEncodingException e) {
                logger.debug("Could not decode username or password header");
            }
            System.out.println("setting state value");
            state.put(stateKey, value);
        }
    }

    private void updateStateIfPresent(TreeContext context, boolean hasValue, String headerName, String stateKey,
            JsonValue state) throws NodeProcessException {
        if (hasValue) {
        	System.out.println("inside updateStateIfPresent");
            List<String> values = context.request.headers.get(headerName);
            System.out.println(headerName+ ":" + values);
            if (values.size() != 1) {
            	 System.out.println("expecting only one header value for username and/or password but size is {}" +
                         values.size());
                logger.error("expecting only one header value for username and/or password but size is {}",
                        values.size());
                throw new NodeProcessException("Expecting only one header value for username and/or password "
                        + "but size is" + values.size());
            }
            String value = values.get(0);
            System.out.println(stateKey+ ":" + value);
            try {
                if (StringUtils.isNotEmpty(value)) {
                    value = MimeUtility.decodeText(value);
                }
            } catch (UnsupportedEncodingException e) {
                logger.debug("Could not decode username or password header");
            }
            System.out.println("setting state value");
            state.put(stateKey, value);
        }
    }

    private Action.ActionBuilder goTo(boolean outcome) {
        return Action.goTo(outcome ? TRUE_OUTCOME_ID : FALSE_OUTCOME_ID);
    }

    private boolean isOnWhiteList(List<String> referers) {
        Set<String> configReferers = config.referrerWhiteList();
        for (String referer : referers) {
            if (configReferers.contains(referer)) {
                return true;
            }
        }
        return false;
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = ZeroPageLoginNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(TRUE_OUTCOME_ID, bundle.getString("trueOutcome")),
                    new Outcome(FALSE_OUTCOME_ID, bundle.getString("falseOutcome")));
        }
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[] {
            new OutputState(USERNAME, singletonMap(TRUE_OUTCOME_ID, false)),
            new OutputState(PASSWORD, singletonMap(TRUE_OUTCOME_ID, false))
        };
    }
}
