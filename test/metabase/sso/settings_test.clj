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

(deftest azure-tenant-id-setter-rejects-multi-tenant-aliases-test
  (testing "setter rejects common/organizations/consumers endpoint aliases"
    (mt/with-temporary-setting-values [azure-tenant-id nil]
      (doseq [bad ["common" "organizations" "consumers"]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"Multi-tenant Azure endpoints"
                              (sso.settings/azure-tenant-id! bad))
            (str "must reject " bad)))))
  (testing "setter accepts a tenant GUID"
    (mt/with-temporary-setting-values [azure-tenant-id nil]
      (sso.settings/azure-tenant-id! "11111111-1111-1111-1111-111111111111")
      (is (= "11111111-1111-1111-1111-111111111111" (sso.settings/azure-tenant-id))))))

(deftest azure-auth-enabled-setter-test
  (testing "Cannot enable Azure SSO unless all mandatory settings are present"
    (mt/with-temporary-setting-values [azure-tenant-id nil
                                       azure-client-id nil
                                       azure-client-secret nil
                                       azure-auth-enabled false]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Azure SSO is not configured"
                            (sso.settings/azure-auth-enabled! true)))))
  (testing "Enabling works once configured"
    (mt/with-temporary-setting-values [azure-tenant-id "11111111-1111-1111-1111-111111111111"
                                       azure-client-id "22222222-2222-2222-2222-222222222222"
                                       azure-client-secret "some-secret"
                                       azure-auth-enabled false]
      (sso.settings/azure-auth-enabled! true)
      (is (true? (sso.settings/azure-auth-enabled)))
      (sso.settings/azure-auth-enabled! false)
      (is (false? (sso.settings/azure-auth-enabled))))))

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
