(ns metabase.sso.api.azure-sso-test
  (:require
   [buddy.core.codecs :as codecs]
   [buddy.core.nonce :as nonce]
   [clojure.string :as str]
   [clojure.test :refer :all]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.test :as mt]
   [metabase.test.http-client :as client]
   [metabase.util.encryption :as encryption]))

(def ^:private tenant-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
(def ^:private client-id "11111111-2222-3333-4444-555555555555")
(def ^:private client-secret "not-a-real-secret")

(def ^:private test-secret
  (encryption/secret-key->hash
   (codecs/bytes->hex (nonce/random-bytes 16))))

(defmacro ^:private with-test-encryption! [& body]
  `(with-redefs [encryption/default-secret-key test-secret]
     ~@body))

(def ^:private discovery-doc
  {:authorization_endpoint (format "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" tenant-id)
   :token_endpoint         (format "https://login.microsoftonline.com/%s/oauth2/v2.0/token" tenant-id)
   :jwks_uri               (format "https://login.microsoftonline.com/%s/discovery/v2.0/keys" tenant-id)})

(defn- do-with-url-prefix-disabled
  "Mirror the Slack Connect integration test fixture: /auth/sso/* endpoints are
   mounted below the root, not below /api, so the test client must skip its
   default /api prefix."
  [thunk]
  (binding [client/*url-prefix* ""]
    (thunk)))

(use-fixtures :each do-with-url-prefix-disabled)

(deftest sso-initiate-requires-enabled-test
  (testing "GET /auth/sso/azure returns 400 when Azure SSO is disabled"
    (mt/with-temporary-raw-setting-values [azure-auth-enabled "false"]
      (let [resp (mt/client :get 400 "/auth/sso/azure" {:request-options {:redirect-strategy :none}})]
        (is (re-find #"not enabled" (str resp)))))))

(deftest sso-initiate-redirects-when-enabled-test
  (testing "GET /auth/sso/azure redirects to login.microsoftonline.com when enabled"
    (with-test-encryption!
      (mt/with-temporary-raw-setting-values [azure-tenant-id      tenant-id
                                             azure-client-id      client-id
                                             azure-client-secret  client-secret
                                             azure-auth-enabled   "true"]
        (with-redefs [oidc.discovery/discover-oidc-configuration (fn [_issuer] discovery-doc)]
          (let [response (mt/client-full-response :get 302 "/auth/sso/azure"
                                                  {:request-options {:redirect-strategy :none}})
                location (get-in response [:headers "Location"])]
            (is (some? location))
            (is (str/starts-with? location
                                  (format "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
                                          tenant-id)))
            (is (str/includes? location (str "client_id=" client-id)))
            (is (str/includes? location "scope=openid%20email%20profile%20offline_access"))
            (testing "encrypted OIDC state cookie is set"
              (let [cookie (->> (get-in response [:headers "Set-Cookie"])
                                (filter #(str/includes? % "metabase.OIDC_STATE"))
                                first)]
                (is (some? cookie))))))))))

(deftest sso-callback-rejects-invalid-state-test
  (testing "GET /auth/sso/azure/callback rejects a callback with no OIDC state cookie"
    (with-test-encryption!
      (mt/with-temporary-raw-setting-values [azure-tenant-id      tenant-id
                                             azure-client-id      client-id
                                             azure-client-secret  client-secret
                                             azure-auth-enabled   "true"]
        (with-redefs [oidc.discovery/discover-oidc-configuration (fn [_issuer] discovery-doc)]
          (mt/client :get 401 "/auth/sso/azure/callback?code=abc&state=zzz"
                     {:request-options {:redirect-strategy :none}}))))))
