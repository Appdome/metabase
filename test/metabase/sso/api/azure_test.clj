(ns metabase.sso.api.azure-test
  (:require
   [clojure.test :refer :all]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.sso.settings :as sso.settings]
   [metabase.test :as mt]))

(def ^:private tenant-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
(def ^:private client-id "11111111-2222-3333-4444-555555555555")
(def ^:private client-secret "not-a-real-secret")

(def ^:private discovery-doc
  {:authorization_endpoint "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/authorize"
   :token_endpoint         "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token"
   :jwks_uri               "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/discovery/v2.0/keys"})

(deftest get-settings-requires-superuser-test
  (testing "GET /api/azure/settings rejects non-superusers"
    (mt/user-http-request :rasta :get 403 "azure/settings")))

(deftest get-settings-masks-client-secret-test
  (mt/with-temporary-raw-setting-values [azure-tenant-id     tenant-id
                                         azure-client-id     client-id
                                         azure-client-secret client-secret]
    (let [resp (mt/user-http-request :crowberto :get 200 "azure/settings")]
      (is (= tenant-id (:azure-tenant-id resp)))
      (is (= client-id (:azure-client-id resp)))
      (is (nil? (:azure-client-secret resp))
          "raw client secret must not be echoed back")
      (is (= "configured" (:azure-client-secret-status resp)))
      (is (true? (:azure-auth-configured resp))))))

(deftest put-settings-updates-admin-editable-fields-test
  (mt/with-temporary-setting-values [azure-attribute-email "preferred_username"
                                     azure-attribute-firstname "given_name"
                                     azure-attribute-lastname "family_name"
                                     azure-attribute-groups "groups"
                                     azure-group-sync false
                                     azure-group-mappings {}
                                     azure-user-provisioning-enabled? true]
    (mt/user-http-request :crowberto :put 200 "azure/settings"
                          {:azure-attribute-email "email"
                           :azure-attribute-firstname "first"
                           :azure-attribute-lastname "last"
                           :azure-attribute-groups "roles"
                           :azure-group-sync true
                           :azure-group-mappings {"group-a" [1]}
                           :azure-user-provisioning-enabled? false})
    (is (= "email" (sso.settings/azure-attribute-email)))
    (is (= "first" (sso.settings/azure-attribute-firstname)))
    (is (= "last" (sso.settings/azure-attribute-lastname)))
    (is (= "roles" (sso.settings/azure-attribute-groups)))
    (is (true? (sso.settings/azure-group-sync)))
    (is (= {"group-a" [1]} (sso.settings/azure-group-mappings)))
    (is (false? (sso.settings/azure-user-provisioning-enabled?)))))

(deftest put-settings-requires-superuser-test
  (testing "PUT /api/azure/settings rejects non-superusers"
    (mt/user-http-request :rasta :put 403 "azure/settings"
                          {:azure-attribute-email "email"})))

(deftest test-endpoint-unconfigured-test
  (mt/with-temporary-raw-setting-values [azure-tenant-id nil
                                         azure-client-id nil
                                         azure-client-secret nil]
    (let [resp (mt/user-http-request :crowberto :post 200 "azure/test")]
      (is (= "ERROR" (:status resp)))
      (is (re-find #"not configured" (:message resp))))))

(deftest test-endpoint-success-test
  (mt/with-temporary-raw-setting-values [azure-tenant-id     tenant-id
                                         azure-client-id     client-id
                                         azure-client-secret client-secret]
    (with-redefs [oidc.discovery/discover-oidc-configuration (fn [_issuer] discovery-doc)]
      (let [resp (mt/user-http-request :crowberto :post 200 "azure/test")]
        (is (= "SUCCESS" (:status resp)))
        (is (= (format "https://login.microsoftonline.com/%s/v2.0" tenant-id)
               (:issuer resp)))
        (is (= (:authorization_endpoint discovery-doc) (:authorization-endpoint resp)))))))

(deftest test-endpoint-discovery-failure-test
  (mt/with-temporary-raw-setting-values [azure-tenant-id     tenant-id
                                         azure-client-id     client-id
                                         azure-client-secret client-secret]
    (with-redefs [oidc.discovery/discover-oidc-configuration (fn [_issuer] nil)]
      (let [resp (mt/user-http-request :crowberto :post 200 "azure/test")]
        (is (= "ERROR" (:status resp)))
        (is (re-find #"discovery" (:message resp)))))))
