(ns metabase.sso.integrations.azure
  "Azure AD (Microsoft Entra ID) SSO route-handler glue.

   Two public endpoints wired elsewhere:
   - `GET /auth/sso/azure`          — [[sso-initiate]] redirects to Azure.
   - `GET /auth/sso/azure/callback` — [[sso-callback]] finishes the login.

   Both delegate to the generic OIDC stack via `:provider/azure`
   ([[metabase.sso.providers.azure]]), which itself derives from
   `:provider/oidc`. No Azure-specific crypto or token validation lives in
   this namespace."
  (:require
   [java-time.api :as t]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.core :as sso]
   [metabase.sso.oidc.state :as oidc.state]
   [metabase.sso.settings :as sso.settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(defn- azure-redirect-uri
  []
  (str (system/site-url) "/auth/sso/azure/callback"))

(defn- check-azure-prereqs!
  []
  (when-not (sso.settings/azure-auth-enabled)
    (throw (ex-info (tru "Azure SSO is not enabled")
                    {:status-code 400}))))

(defn sso-initiate
  "Initiate the Azure SSO flow. Redirects to the Azure AD authorization endpoint."
  [request]
  (check-azure-prereqs!)
  (let [{:keys [redirect]} (:params request)
        redirect-url (if (and redirect (oidc.state/valid-redirect-url? redirect))
                       redirect
                       "/")
        auth-result  (auth-identity/authenticate
                      :provider/azure
                      (assoc request
                             :redirect-uri (azure-redirect-uri)
                             :oidc-provider :azure
                             :final-redirect redirect-url))]
    (if (= :redirect (:success? auth-result))
      (sso/wrap-oidc-redirect auth-result
                              request
                              :azure
                              redirect-url
                              {:browser-id (:browser-id request)})
      (throw (ex-info (or (:message auth-result) (tru "Failed to initiate Azure authentication"))
                      {:status-code 500})))))

(defn sso-callback
  "Handle the Azure SSO callback after the user authenticates with Entra ID."
  [request]
  (check-azure-prereqs!)
  (let [{:keys [code state]} (:params request)
        login-result (auth-identity/login!
                      :provider/azure
                      (assoc request
                             :code code
                             :state state
                             :oidc-provider :azure
                             :redirect-uri (azure-redirect-uri)
                             :device-info (request/device-info request)))]
    (cond
      (:success? login-result)
      (let [final-redirect (or (:redirect-url login-result) "/")
            base-response  (-> (response/redirect final-redirect)
                               (sso/clear-oidc-state-cookie))]
        (log/infof "Azure SSO login successful for user %s"
                   (get-in login-result [:user :email]))
        (if-let [session (:session login-result)]
          (request/set-session-cookies request
                                       base-response
                                       session
                                       (t/zoned-date-time (t/zone-id "GMT")))
          base-response))

      :else
      (let [error-msg (or (:message login-result) (tru "Azure SSO authentication failed"))]
        (log/errorf "Azure SSO authentication failed: %s" error-msg)
        (throw (ex-info (str error-msg) {:status-code 401 :errors (:error login-result)}))))))
