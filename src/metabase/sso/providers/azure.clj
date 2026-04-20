(ns metabase.sso.providers.azure
  "Azure AD (Microsoft Entra ID) SSO provider.

   Azure AD is a standards-compliant OIDC identity provider. This namespace does
   not reimplement the OIDC flow — it derives `:provider/azure` from the generic
   `:provider/oidc` and plugs in Azure-specific behavior via `:around` aux methods:

   - `authenticate`: inject the Azure OIDC config into the request (so the
     generic OIDC provider builds authorization URLs and validates tokens
     against the configured tenant), then post-process the result to stamp
     `:sso_source :azure` and override `:provider-id` with the tenant-wide
     immutable `oid` claim.

   - `login!`: after the user is provisioned/fetched, run group sync if
     `azure-group-sync` is enabled."
  (:require
   [metabase.auth-identity.core :as auth-identity]
   [metabase.sso.azure :as sso.azure]
   ;; side-effect require: registers :provider/oidc hierarchy + methods
   [metabase.sso.providers.oidc]
   [metabase.util.log :as log]
   [methodical.core :as methodical]))

(set! *warn-on-reflection* true)

(derive :provider/azure :provider/oidc)

(defn- post-process-authentication-result
  "Post-process the result of an OIDC authentication so Azure-specific conventions
   are applied — `sso_source` becomes `:azure` and the provider-id is the
   tenant-wide immutable `oid` claim (falling back to `sub`).

   Expects the `:claims` shape produced by `metabase.sso.providers.oidc/authenticate`
   on a successful callback. Initiate-flow and failure results pass through."
  [result]
  (if (and (:success? result) (:claims result))
    (let [stamped (assoc-in result [:user-data :sso_source] :azure)
          pid     (sso.azure/claim-provider-id (:claims result))]
      (cond-> stamped
        pid (assoc-in [:user-data :provider-id] pid)
        pid (assoc :provider-id pid)))
    result))

(methodical/defmethod auth-identity/authenticate :around :provider/azure
  [provider request]
  (let [cfg      (sso.azure/config-for-azure (:redirect-uri request))
        request' (cond-> request
                   cfg (assoc :oidc-config cfg))]
    (post-process-authentication-result (next-method provider request'))))

(methodical/defmethod auth-identity/login! :around :provider/azure
  [provider request]
  (let [result (next-method provider request)]
    ;; Only the callback branch carries `:claims`; the initiate branch returns
    ;; `:success? :redirect` with no claims, so gating on `:claims` cleanly
    ;; scopes group sync to completed logins.
    (when (and (:claims result) (get-in result [:user :id]))
      (try
        (sso.azure/maybe-sync-groups! (get-in result [:user :id])
                                      (:claims result))
        (catch Exception e
          (log/error e "Azure group sync failed; continuing login"))))
    result))
