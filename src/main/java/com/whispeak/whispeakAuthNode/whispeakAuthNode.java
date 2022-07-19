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
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.whispeak.whispeakAuthNode;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = whispeakAuthNode.Config.class)
public class whispeakAuthNode extends AbstractDecisionNode {

    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private final Logger logger = LoggerFactory.getLogger(whispeakAuthNode.class);
    private final Config config;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Whispeak APIP Key
         */
        @Attribute(order = 100)
        default String wsAPIKey() {
            return "";
        }

        /**
         * Whispeak customer ID
         */
        @Attribute(order = 200)
        default String wsCustomer() {
            return "forgerock";
        }

        /**
         * Whispeak Applicatiion to use
         */
        @Attribute(order = 300)
        default String wsApplication() {
            return "with-asr";
        }

        /**
         * Whispeak Configuration to use
         */
        @Attribute(order = 400)
        default String wsAppConfig() {
            return "with-asr-20-8-3";
        }

        /**
         * Whispeak API base URI
         */
        @Attribute(order = 500)
        default String wsBaseURI() {
            return ".whispeak.io/v1/apps/";
        }

        /**
         * Use Whispeak API with HTTPS
         */
        @Attribute(order = 600)
            default boolean wsIsHTTPS() {
                return false;
            }

        /**
         * Whispeak Enroll/UnEnroll voice URI
         * Action depends on HTTP action : 
         * POST: Enroll a voice signature
         * DELETE: Un-enroll a voice signature
         */
        @Attribute(order = 700)
        default String wsEnrollURI() {
            return "/enroll";
        }

        /**
         * Whispeak Authentication voice URI
         */
        @Attribute(order = 800)
        default String wsAuthURI() {
            return "/auth";
        }

        /**
         * Defines the attribute in user profile where to store Whispeak user id
         * jsonResultCheckVoice.id
         */
        @Attribute(order = 900)
        default String wsIdAttributeInProfile() {
            return "fr-attr-istr2";
        }

        /**
         * Defines the attribute in user profile where to store Whispeak Revoke links
         * "api_link:"+jsonResultCheckVoice.revocation.api_link,
         * "signature_secret_password:"+jsonResultCheckVoice.revocation.signature_secret_password,
         * "ui_link:"+jsonResultCheckVoice.revocation.ui_link
         */
        @Attribute(order = 1000)
        default String wsRevokeAttributeInProfile() {
            return "fr-attr-imulti1";
        }

        /**
         * Store Voice signature in FOrgeRock user's profile?
         */
        @Attribute(order = 1100)
        default boolean wsStoreSignInFR() {
            return false;
        }

        /**
         * Defines the attribute in user profile where to store 
         * Whispeak user's signature
         */
        @Attribute(order = 1200)
        default String wsVoiceSignature() {
            return "";
        }




        /**
         * The script to send to client to record the voice to enroll
         *
         * @return The script configuration.
         *
        @Attribute(order = 1300)
        @ScriptContext(AUTHENTICATION_TREE_DECISION_NODE_NAME)
        default Script wsEnrollScript() {
            return Script.EMPTY_SCRIPT;
        }

        /**
         * The script to send to client to record the voice to authenticate
         *
         * @return The script configuration.
         *
        @Attribute(order = 1300)
        @ScriptContext(AUTHENTICATION_TREE_DECISION_NODE_NAME)
        default Script wsAuthScript() {
            return Script.EMPTY_SCRIPT;
        }*/

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public whispeakAuthNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
/* 
        AMIdentity userIdentity = IdUtils.getIdentity(username, realm.asDN());
        try {
            if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive())) {
                return goTo(true)
                        .replaceSharedState(context.sharedState.copy().put(USERNAME, username))
                        .replaceTransientState(context.transientState.copy().put(PASSWORD, password))
                        .build();
            }
        } catch (IdRepoException | SSOException e) {
            logger.warn("Error locating user '{}' ", username, e);
        }*/
        return goTo(false).build();
    }

}
