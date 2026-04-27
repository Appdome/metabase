(ns metabase.sso.api.azure-sso
  "HTTP routes for the public `/auth/sso/azure` flow.
   Admin configuration endpoints live in [[metabase.sso.api.azure]]."
  (:require
   [metabase.api.macros :as api.macros]
   [metabase.sso.integrations.azure :as azure-integration]
   [metabase.util.log :as log]))

;; GET /auth/sso/azure
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/"
  "Initiate the Azure AD SSO flow."
  [_route-params _query-params _body request]
  (try
    (azure-integration/sso-initiate request)
    (catch Throwable e
      (log/error e "Error initiating Azure SSO")
      (throw e))))

;; GET /auth/sso/azure/callback
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/callback"
  "Azure AD OIDC callback."
  [_route-params _query-params _body request]
  (try
    (azure-integration/sso-callback request)
    (catch Throwable e
      (log/error e "Error handling Azure SSO callback")
      (throw e))))

(def ^{:arglists '([request respond raise])} routes
  "`/auth/sso/azure` routes."
  (api.macros/ns-handler *ns*))
