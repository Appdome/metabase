(ns metabase.sso.api.azure
  "`/api/azure` admin endpoints.

   Sensitive Azure settings — tenant/client/secret and the master enable switch —
   are environment-only (see [[metabase.sso.settings]] `:setter :none`). This
   admin surface is limited to attribute claim mapping, group synchronisation
   configuration, and the user-provisioning toggle."
  (:require
   [metabase.api.common :as api]
   [metabase.api.macros :as api.macros]
   [metabase.settings.core :as setting]
   [metabase.sso.azure :as sso.azure]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.sso.settings :as sso.settings]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/settings"
  "Return the current Azure SSO configuration. Env-managed fields (tenant ID,
   client ID, client secret, master enable switch) are reported read-only."
  [_route-params _query-params _body]
  (api/check-superuser)
  {:azure-auth-configured           (sso.settings/azure-auth-configured)
   :azure-auth-enabled              (sso.settings/azure-auth-enabled)
   :azure-tenant-id                 (sso.settings/azure-tenant-id)
   :azure-client-id                 (sso.settings/azure-client-id)
   ;; never return the raw client secret; just report whether one is on file
   :azure-client-secret-configured? (boolean (sso.settings/azure-client-secret))
   :azure-attribute-email           (sso.settings/azure-attribute-email)
   :azure-attribute-firstname       (sso.settings/azure-attribute-firstname)
   :azure-attribute-lastname        (sso.settings/azure-attribute-lastname)
   :azure-attribute-groups          (sso.settings/azure-attribute-groups)
   :azure-group-sync                (sso.settings/azure-group-sync)
   :azure-group-mappings            (sso.settings/azure-group-mappings)
   :azure-user-provisioning-enabled? (sso.settings/azure-user-provisioning-enabled?)})

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :put "/settings"
  "Update the admin-editable Azure SSO settings. Tenant, client, secret and the
   master enable switch are read-only here — they are configured via environment
   variables and cannot be mutated at runtime.

   Callers should send the complete desired configuration; any field omitted
   here (or sent as `null`) is cleared back to its default."
  [_route-params
   _query-params
   body :- [:map
            [:azure-attribute-email            {:optional true} [:maybe :string]]
            [:azure-attribute-firstname        {:optional true} [:maybe :string]]
            [:azure-attribute-lastname         {:optional true} [:maybe :string]]
            [:azure-attribute-groups           {:optional true} [:maybe :string]]
            [:azure-group-sync                 {:optional true} [:maybe :boolean]]
            [:azure-group-mappings             {:optional true} [:maybe [:or :string [:map-of :string [:sequential pos-int?]]]]]
            [:azure-user-provisioning-enabled? {:optional true} [:maybe :boolean]]]]
  (api/check-superuser)
  (t2/with-transaction [_conn]
    (setting/set-many! (select-keys body [:azure-attribute-email
                                          :azure-attribute-firstname
                                          :azure-attribute-lastname
                                          :azure-attribute-groups
                                          :azure-group-sync
                                          :azure-group-mappings
                                          :azure-user-provisioning-enabled?]))))

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :post "/test"
  "Dry-run Azure SSO configuration: resolve the OIDC discovery document for the
   configured tenant and confirm the authorization endpoint is reachable."
  [_route-params _query-params _body]
  (api/check-superuser)
  (if-not (sso.settings/azure-auth-configured)
    {:status  "ERROR"
     :message (tru "Azure SSO is not configured. Set MB_AZURE_TENANT_ID, MB_AZURE_CLIENT_ID, and MB_AZURE_CLIENT_SECRET.")}
    (let [issuer (sso.azure/issuer-uri)
          doc    (try
                   (oidc.discovery/discover-oidc-configuration issuer)
                   (catch Throwable e
                     (log/warn e "Azure discovery failed")
                     nil))]
      (cond
        (nil? doc)
        {:status  "ERROR"
         :issuer  issuer
         :message (tru "Could not fetch OIDC discovery document from Azure. Check the tenant ID and network reachability.")}

        (not (:authorization_endpoint doc))
        {:status  "ERROR"
         :issuer  issuer
         :message (tru "Azure discovery document did not advertise an authorization endpoint.")}

        :else
        {:status                 "SUCCESS"
         :issuer                 issuer
         :authorization-endpoint (:authorization_endpoint doc)
         :token-endpoint         (:token_endpoint doc)
         :jwks-uri               (:jwks_uri doc)}))))

(def ^{:arglists '([request respond raise])} routes
  "`/api/azure` routes."
  (api.macros/ns-handler *ns*))
