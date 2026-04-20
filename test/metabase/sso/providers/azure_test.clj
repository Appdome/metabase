(ns metabase.sso.providers.azure-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer :all]
   [metabase.auth-identity.provider :as provider]
   [metabase.permissions.models.permissions-group-membership :as pgm]
   [metabase.sso.azure :as sso.azure]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.sso.providers.azure :as sso.providers.azure]
   [metabase.sso.settings :as sso.settings]
   [metabase.test :as mt]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:private tenant-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
(def ^:private client-id "11111111-2222-3333-4444-555555555555")
(def ^:private client-secret "not-a-real-secret")

(def ^:private redirect-uri "https://metabase.example.com/auth/sso/azure/callback")

(def ^:private discovery-doc
  {:authorization_endpoint (format "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" tenant-id)
   :token_endpoint         (format "https://login.microsoftonline.com/%s/oauth2/v2.0/token" tenant-id)
   :jwks_uri               (format "https://login.microsoftonline.com/%s/discovery/v2.0/keys" tenant-id)})

(defmacro ^:private with-azure-configured [& body]
  ;; Azure secrets live behind `:setter :none` (env-only), so seed raw setting
  ;; storage instead of going through a setter.
  `(mt/with-temporary-raw-setting-values [~'azure-tenant-id ~tenant-id
                                          ~'azure-client-id ~client-id
                                          ~'azure-client-secret ~client-secret
                                          ~'azure-auth-enabled "true"]
     ~@body))

(deftest issuer-uri-test
  (testing "issuer-uri returns nil when tenant is unset"
    (mt/with-temporary-raw-setting-values [azure-tenant-id nil]
      (is (nil? (sso.azure/issuer-uri)))))
  (testing "issuer-uri produces the v2.0 Azure endpoint for the configured tenant"
    (mt/with-temporary-raw-setting-values [azure-tenant-id tenant-id]
      (is (= (format "https://login.microsoftonline.com/%s/v2.0" tenant-id)
             (sso.azure/issuer-uri))))))

(deftest config-for-azure-test
  (testing "returns nil when Azure settings are not fully configured"
    (mt/with-temporary-raw-setting-values [azure-tenant-id nil
                                           azure-client-id nil
                                           azure-client-secret nil]
      (is (nil? (sso.azure/config-for-azure redirect-uri)))))
  (testing "returns a full OIDC config map when Azure is configured"
    (with-azure-configured
      (let [cfg (sso.azure/config-for-azure redirect-uri)]
        (is (= client-id (:client-id cfg)))
        (is (= client-secret (:client-secret cfg)))
        (is (= (format "https://login.microsoftonline.com/%s/v2.0" tenant-id)
               (:issuer-uri cfg)))
        (is (= redirect-uri (:redirect-uri cfg)))
        (is (= ["openid" "email" "profile" "offline_access"] (:scopes cfg)))
        (is (= "preferred_username" (:attribute-email cfg)))
        (is (= "given_name" (:attribute-firstname cfg)))
        (is (= "family_name" (:attribute-lastname cfg)))))))

(deftest ^:parallel claim-provider-id-test
  (testing "oid claim is preferred as provider-id"
    (is (= "oid-value" (sso.azure/claim-provider-id {:oid "oid-value" :sub "sub-value"}))))
  (testing "sub claim is the fallback when oid is absent"
    (is (= "sub-value" (sso.azure/claim-provider-id {:sub "sub-value"}))))
  (testing "returns nil when both are missing"
    (is (nil? (sso.azure/claim-provider-id {})))))

(deftest authenticate-initiate-builds-azure-redirect-test
  (testing "authenticate :provider/azure initiates the flow with the Azure authorization endpoint"
    (with-azure-configured
      (with-redefs [oidc.discovery/discover-oidc-configuration (fn [_issuer] discovery-doc)]
        (let [request {:redirect-uri redirect-uri}
              result  (provider/authenticate :provider/azure request)]
          (is (= :redirect (:success? result)))
          (is (str/includes? (:redirect-url result)
                             (format "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" tenant-id)))
          (is (str/includes? (:redirect-url result) (str "client_id=" client-id)))
          (is (str/includes? (:redirect-url result) "scope=openid%20email%20profile%20offline_access")))))))

(def ^:private post-process-authentication-result
  #'sso.providers.azure/post-process-authentication-result)

(deftest ^:parallel post-process-authentication-result-test
  (testing "successful callback result: oid -> provider-id, sso_source -> :azure"
    (let [input  {:success? true
                  :claims {:oid "azure-oid-xyz"
                           :sub "should-be-ignored"
                           :email "robin@example.com"}
                  :user-data {:email "robin@example.com"
                              :first_name "Robin"
                              :last_name "Finch"
                              :provider-id "should-be-ignored"
                              :sso_source :oidc}
                  :provider-id "should-be-ignored"}
          result (post-process-authentication-result input)]
      (is (true? (:success? result)))
      (is (= "azure-oid-xyz" (:provider-id result)))
      (is (= "azure-oid-xyz" (get-in result [:user-data :provider-id])))
      (is (= :azure (get-in result [:user-data :sso_source])))))

  (testing "falls back to sub when oid claim is absent"
    (let [result (post-process-authentication-result
                  {:success? true
                   :claims {:sub "sub-only"}
                   :user-data {:email "robin@example.com"
                               :provider-id "should-be-ignored"
                               :sso_source :oidc}
                   :provider-id "should-be-ignored"})]
      (is (= "sub-only" (:provider-id result)))
      (is (= :azure (get-in result [:user-data :sso_source])))))

  (testing "initiate-flow result (no :claims) is passed through unchanged"
    (let [redirect {:success? :redirect :redirect-url "https://login.microsoftonline.com/..." :state "s" :nonce "n"}]
      (is (= redirect (post-process-authentication-result redirect)))))

  (testing "failed authentication result passes through unchanged"
    (let [failure {:success? false :error :invalid-token :message "bad"}]
      (is (= failure (post-process-authentication-result failure))))))

(deftest sync-user-groups!-test
  (mt/with-temp [:model/PermissionsGroup {grp-a :id} {:name "Engineering"}
                 :model/PermissionsGroup {grp-b :id} {:name "Finance"}
                 :model/PermissionsGroup {grp-c :id} {:name "Manual-only"}
                 :model/User             {uid :id}   {:email "robin@example.com"}]
    (let [mappings     {"azure-eng" [grp-a] "azure-fin" [grp-b]}]
      (testing "users are added to mapped Metabase groups matching their Azure groups"
        (sso.azure/sync-user-groups! uid #{"azure-eng"} mappings)
        (is (contains? (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))
                       grp-a))
        (is (not (contains? (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))
                            grp-b))))

      (testing "re-sync with a different Azure group moves membership between managed groups"
        (sso.azure/sync-user-groups! uid #{"azure-fin"} mappings)
        (let [gids (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))]
          (is (contains? gids grp-b))
          (is (not (contains? gids grp-a)))))

      (testing "manually-assigned memberships in groups NOT listed in mappings are preserved"
        (pgm/add-user-to-group! uid grp-c)
        (sso.azure/sync-user-groups! uid #{} mappings)
        (let [gids (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))]
          (is (contains? gids grp-c) "unmapped group membership must remain untouched")
          (is (not (contains? gids grp-a)))
          (is (not (contains? gids grp-b))))))))

(def ^:private extract-group-oids #'sso.azure/extract-group-oids)

(deftest extract-group-oids-test
  (testing "reads the configured groups claim and coerces to a set of strings"
    (mt/with-temporary-setting-values [azure-attribute-groups "groups"]
      (is (= #{"g1" "g2"} (extract-group-oids {:groups ["g1" "g2"]})))
      (is (= #{} (extract-group-oids {:groups nil})))
      (is (= #{} (extract-group-oids {})))
      (is (= #{"only-one"} (extract-group-oids {:groups "only-one"}))
          "Azure may emit a bare string when only one group is present")
      (is (= #{"42"} (extract-group-oids {:groups [42]}))
          "non-string entries are coerced to strings")))
  (testing "honors a custom `azure-attribute-groups` override"
    (mt/with-temporary-setting-values [azure-attribute-groups "wids"]
      (is (= #{"x"} (extract-group-oids {:wids ["x"]})))
      (is (= #{} (extract-group-oids {:groups ["should-be-ignored"]}))))))

(deftest maybe-sync-groups!-test
  (mt/with-temp [:model/PermissionsGroup {grp :id} {:name "Payroll"}
                 :model/User             {uid :id} {:email "heron@example.com"}]
    (let [mappings {"azure-payroll" [grp]}]
      (testing "no-op when azure-group-sync is disabled"
        (mt/with-temporary-setting-values [azure-group-sync false
                                           azure-group-mappings mappings]
          (sso.azure/maybe-sync-groups! uid {:groups ["azure-payroll"]})
          (is (not (contains? (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))
                              grp)))))
      (testing "syncs when azure-group-sync is enabled"
        (mt/with-temporary-setting-values [azure-group-sync true
                                           azure-group-mappings mappings]
          (sso.azure/maybe-sync-groups! uid {:groups ["azure-payroll"]})
          (is (contains? (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id uid))
                         grp))))
      (testing "no-op when user-id or claims missing"
        (mt/with-temporary-setting-values [azure-group-sync true
                                           azure-group-mappings mappings]
          (is (nil? (sso.azure/maybe-sync-groups! nil {:groups ["x"]})))
          (is (nil? (sso.azure/maybe-sync-groups! uid nil))))))))
