(ns metabase.sso.azure
  "Helpers for Azure AD (Microsoft Entra ID) SSO via OIDC.

   Azure AD is a standards-compliant OIDC identity provider. Metabase's generic
   OIDC provider ([[metabase.sso.providers.oidc]]) does the heavy lifting — the
   Azure provider is a thin wrapper that plugs tenant-specific settings into the
   same machinery and adds Azure-flavored post-processing (stable `oid` subject,
   group sync).

   Issuer URI for v2 endpoint:
     https://login.microsoftonline.com/<tenant-id>/v2.0

   The discovery document is fetched on first use by [[metabase.sso.oidc.discovery]]
   and cached; the authorization, token and JWKS endpoints are read from it."
  (:require
   [clojure.set :as set]
   [metabase.permissions.models.permissions-group-membership :as pgm]
   [metabase.sso.settings :as sso.settings]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:private default-scopes
  ["openid" "email" "profile" "offline_access"])

(defn issuer-uri
  "Build the Azure v2 issuer URI for the configured tenant, or `nil` if no tenant is set."
  []
  (when-let [tenant-id (sso.settings/azure-tenant-id)]
    (format "https://login.microsoftonline.com/%s/v2.0" tenant-id)))

(defn config-for-azure
  "Build the OIDC configuration map expected by `:provider/oidc` for the current Azure settings.

   `redirect-uri` is the per-request callback URL (e.g. `<site>/auth/sso/azure/callback`).
   Returns `nil` if Azure is not configured."
  [redirect-uri]
  (when (sso.settings/azure-auth-configured)
    {:client-id           (sso.settings/azure-client-id)
     :client-secret       (sso.settings/azure-client-secret)
     :issuer-uri          (issuer-uri)
     :redirect-uri        redirect-uri
     :scopes              default-scopes
     :attribute-email     (sso.settings/azure-attribute-email)
     :attribute-firstname (sso.settings/azure-attribute-firstname)
     :attribute-lastname  (sso.settings/azure-attribute-lastname)}))

(defn claim-provider-id
  "Pick the stable provider identifier from Azure ID token claims.

   Prefers the tenant-wide immutable `oid` claim. Falls back to `sub` (per-app
   subject) if `oid` is absent — this only happens on some B2C flows or when the
   admin forgot to add the `oid` optional claim in Azure Token Configuration."
  [claims]
  (or (:oid claims) (:sub claims)))

(defn- extract-group-oids
  "Read the configured groups claim out of `claims` and coerce it to a set of strings."
  [claims]
  (let [groups-attr (keyword (sso.settings/azure-attribute-groups))
        groups      (get claims groups-attr)]
    (cond
      (nil? groups)        #{}
      (sequential? groups) (set (map str groups))
      :else                #{(str groups)})))

(defn sync-user-groups!
  "Partial-authoritative group sync.

   For each Azure group object ID in `azure-group-oids`, look up the list of
   Metabase group IDs in `mappings` and ensure the user belongs to exactly the
   set of *managed* groups that match. Groups not present as values in
   `mappings` (unmanaged) are left untouched — this prevents the sync from
   removing, e.g., \"All Users\" or ad-hoc memberships.

   Delegates to [[metabase.permissions.models.permissions-group-membership]]
   helpers so that membership invariants (admin flag, tenant-user constraints,
   event emission) stay intact. Note that `add-user-to-groups!` throws if the
   target group and user have mismatched tenant scope — callers that expect
   Azure to feed tenant users must avoid mapping non-tenant Metabase groups.

   Idempotent."
  [user-id azure-group-oids mappings]
  (let [managed-mb-group-ids (into #{} cat (vals mappings))
        desired-mb-group-ids (into #{} cat (vals (select-keys mappings azure-group-oids)))
        current-mb-group-ids (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id user-id))
        to-remove            (set/difference (set/intersection current-mb-group-ids managed-mb-group-ids)
                                             desired-mb-group-ids)
        to-add               (set/difference desired-mb-group-ids current-mb-group-ids)]
    (when (seq to-remove)
      (log/debugf "Azure group sync: user %s leaving Metabase groups %s" user-id (vec to-remove))
      (pgm/remove-user-from-groups! user-id to-remove))
    (when (seq to-add)
      (log/debugf "Azure group sync: user %s joining Metabase groups %s" user-id (vec to-add))
      (pgm/add-user-to-groups! user-id to-add))))

(defn maybe-sync-groups!
  "Run [[sync-user-groups!]] iff `azure-group-sync` is enabled and `user-id` + `claims` are present."
  [user-id claims]
  (when (and user-id claims (sso.settings/azure-group-sync))
    (sync-user-groups! user-id
                       (extract-group-oids claims)
                       (sso.settings/azure-group-mappings))))
