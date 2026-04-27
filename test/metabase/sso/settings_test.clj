(ns metabase.sso.settings-test
  (:require
   [clojure.test :refer :all]
   [metabase.sso.ldap :as ldap]
   [metabase.sso.ldap-test-util :as ldap.test]
   [metabase.sso.settings :as sso.settings]
   [metabase.test :as mt]))

(deftest ldap-enabled-test
  (ldap.test/with-ldap-server!
    (testing "`ldap-enabled` setting validates currently saved LDAP settings"
      (mt/with-temporary-setting-values [ldap-enabled false]
        (with-redefs [ldap/test-current-ldap-details (constantly {:status :ERROR :message "test error"})]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo
                                #"Unable to connect to LDAP server"
                                (sso.settings/ldap-enabled! true))))
        (with-redefs [ldap/test-current-ldap-details (constantly {:status :SUCCESS})]
          (sso.settings/ldap-enabled! true)
          (is (sso.settings/ldap-enabled))

          (sso.settings/ldap-enabled! false)
          (is (not (sso.settings/ldap-enabled))))))))

(deftest ^:parallel send-new-sso-user-admin-email?-test
  (is ((some-fn nil? boolean?) (sso.settings/send-new-sso-user-admin-email?))
      "Make sure this Setting returns a boolean, not some other type of value. (It was returning a function before I fixed it.)"))

(deftest azure-auth-configured-test
  (testing "azure-auth-configured returns false when any mandatory setting is missing"
    (mt/with-temporary-setting-values [azure-tenant-id nil
                                       azure-client-id nil
                                       azure-client-secret nil]
      (is (false? (sso.settings/azure-auth-configured))))
    (mt/with-temporary-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"
                                       azure-client-id nil
                                       azure-client-secret nil]
      (is (false? (sso.settings/azure-auth-configured)))))
  (testing "azure-auth-configured returns true when all three settings present"
    (mt/with-temporary-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"
                                       azure-client-id "22222222-2222-2222-2222-222222222222"
                                       azure-client-secret "some-secret"]
      (is (true? (sso.settings/azure-auth-configured))))))

(deftest ^:parallel valid-azure-tenant-id?-test
  (testing "multi-tenant endpoint aliases are rejected"
    (is (false? (sso.settings/valid-azure-tenant-id? "common")))
    (is (false? (sso.settings/valid-azure-tenant-id? "organizations")))
    (is (false? (sso.settings/valid-azure-tenant-id? "consumers")))
    (is (false? (sso.settings/valid-azure-tenant-id? nil))))
  (testing "tenant GUIDs are accepted"
    (is (true? (sso.settings/valid-azure-tenant-id? "11111111-1111-1111-1111-111111111111")))
    (is (true? (sso.settings/valid-azure-tenant-id? "contoso.onmicrosoft.com")))))

(deftest azure-tenant-id-getter-filters-multi-tenant-aliases-test
  (testing "reading a multi-tenant alias from raw storage returns nil"
    (mt/with-temporary-raw-setting-values [azure-tenant-id "common"]
      (is (nil? (sso.settings/azure-tenant-id))))
    (mt/with-temporary-raw-setting-values [azure-tenant-id "organizations"]
      (is (nil? (sso.settings/azure-tenant-id))))
    (mt/with-temporary-raw-setting-values [azure-tenant-id "consumers"]
      (is (nil? (sso.settings/azure-tenant-id)))))
  (testing "reading a tenant GUID returns it verbatim"
    (mt/with-temporary-raw-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"]
      (is (= "11111111-1111-1111-1111-111111111111" (sso.settings/azure-tenant-id))))))

(deftest azure-auth-enabled-requires-config-test
  (testing "azure-auth-enabled returns false when azure-auth-configured is false"
    (mt/with-temporary-raw-setting-values [azure-tenant-id nil
                                           azure-client-id nil
                                           azure-client-secret nil
                                           azure-auth-enabled "true"]
      (is (false? (sso.settings/azure-auth-enabled)))))
  (testing "azure-auth-enabled reflects the raw env/setting value once configured"
    (mt/with-temporary-raw-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"
                                           azure-client-id "22222222-2222-2222-2222-222222222222"
                                           azure-client-secret "some-secret"
                                           azure-auth-enabled "true"]
      (is (true? (sso.settings/azure-auth-enabled))))
    (mt/with-temporary-raw-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"
                                           azure-client-id "22222222-2222-2222-2222-222222222222"
                                           azure-client-secret "some-secret"
                                           azure-auth-enabled "false"]
      (is (false? (sso.settings/azure-auth-enabled))))))

(deftest azure-secrets-are-not-admin-settable-test
  (testing "`:setter :none` means the generated `!` setters are not defined"
    (is (not (fn? (try (resolve 'metabase.sso.settings/azure-tenant-id!) (catch Throwable _ nil)))))
    (is (not (fn? (try (resolve 'metabase.sso.settings/azure-client-id!) (catch Throwable _ nil)))))
    (is (not (fn? (try (resolve 'metabase.sso.settings/azure-client-secret!) (catch Throwable _ nil)))))
    (is (not (fn? (try (resolve 'metabase.sso.settings/azure-auth-enabled!) (catch Throwable _ nil)))))))

(deftest azure-attribute-defaults-test
  (testing "default claim names match Azure v2 token conventions"
    (is (= "preferred_username" (sso.settings/azure-attribute-email)))
    (is (= "given_name" (sso.settings/azure-attribute-firstname)))
    (is (= "family_name" (sso.settings/azure-attribute-lastname)))
    (is (= "groups" (sso.settings/azure-attribute-groups)))))

(deftest sso-source-enabled?-azure-test
  (testing "sso-source-enabled? returns azure-auth-enabled for :azure source"
    (mt/with-temporary-setting-values [azure-auth-enabled false]
      (is (false? (sso.settings/sso-source-enabled? :azure))))
    (mt/with-temporary-setting-values [azure-tenant-id "tid"
                                       azure-client-id "cid"
                                       azure-client-secret "sec"
                                       azure-auth-enabled true]
      (is (true? (sso.settings/sso-source-enabled? :azure))))))
