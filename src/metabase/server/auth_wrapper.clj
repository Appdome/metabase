(ns metabase.server.auth-wrapper
  (:require
   [metabase.api.util.handlers :as handlers]
   [metabase.config.core :as config]
   [metabase.sso.api.azure-sso :as azure-sso.api]
   [metabase.sso.api.slack-connect :as slack-connect.api]
   [ring.util.response :as response]))

(let [bad-req (response/bad-request {:message "The auth/sso endpoint only exists in enterprise builds"
                                     :status "ee-build-required"})]
  (defn- not-enabled
    [_req respond _raise]
    (respond bad-req)))

(def ^:private ee-missing-routes
  "Fallback routes when EE is not available. Returns 'not enabled' for SSO routes that require EE."
  (handlers/route-map-handler
   {"/auth" {"/sso" not-enabled}
    "/api"  {"/saml" not-enabled
             "/ee"   {"/sso" {"/oidc" not-enabled}}}}))

;; This needs to be injected into [[metabase.server.routes/routes]] -- not [[metabase.api-routes.core/routes]] !!!
(def routes
  "Ring routes for auth API endpoints.
   Slack Connect and Azure AD (OSS) are always available. Other SSO routes (SAML, JWT, custom OIDC) require EE."
  (handlers/routes
   ;; OSS SSO routes
   (handlers/route-map-handler
    {"/auth" {"/sso" {"/slack-connect" slack-connect.api/routes
                      "/azure"         azure-sso.api/routes}}})
   ;; Other SSO routes require EE
   (if (and config/ee-available? (not *compile-files*))
     (requiring-resolve 'metabase-enterprise.sso.api.routes/routes)
     ee-missing-routes)))
