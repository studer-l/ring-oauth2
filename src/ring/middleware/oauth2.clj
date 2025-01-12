(ns ring.middleware.oauth2
  (:require [clj-http.client :as http]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp])
  (:import [java.time Instant]
           [java.util Date]
           [java.security MessageDigest]
           [java.nio.charset StandardCharsets]
           [org.apache.commons.codec.binary Base64]))

(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn- base64 [^bytes bs]
  (String. (Base64/encodeBase64 bs)))

(defn- str->sha256 [^String s]
  (-> (MessageDigest/getInstance "SHA-256")
      (.digest (.getBytes s StandardCharsets/UTF_8))))

(defn- base64url [base64-str]
  (-> base64-str (str/replace "+" "-") (str/replace "/" "_")))

(defn- verifier->challenge [^String verifier]
  (-> verifier str->sha256 base64 base64url (str/replace "=" "")))

(defn- authorize-params [profile request state verifier]
  (-> {:response_type "code"
       :client_id     (:client-id profile)
       :redirect_uri  (redirect-uri profile request)
       :scope         (scopes profile)
       :state         state}
      (cond-> (:pkce? profile)
              (assoc :code_challenge (verifier->challenge verifier)
                     :code_challenge_method "S256"))))

(defn- authorize-uri [profile request state verifier]
  (str (:authorize-uri profile)
       (if (.contains ^String (:authorize-uri profile) "?") "&" "?")
       (codec/form-encode (authorize-params profile request state verifier))))

(defn- random-state []
  (base64url (random/base64 9)))

(defn- random-code-verifier []
  (base64url (random/base64 63)))

(defn- make-launch-handler [{:keys [pkce?] :as profile}]
  (fn handler
    ([{:keys [session] :or {session {}} :as request}]
     (let [state    (random-state)
           verifier (when pkce? (random-code-verifier))
           session' (-> session
                        (assoc ::state state)
                        (cond-> pkce? (assoc ::code-verifier verifier)))]
       (-> (resp/redirect (authorize-uri profile request state verifier))
           (assoc :session session'))))
    ([request respond raise]
     (when-let [response (try (handler request)
                              (catch Exception e (raise e) false))]
       (respond response)))))

(defn- state-matches? [request]
  (= (get-in request [:session ::state])
     (get-in request [:query-params "state"])))

(defn- coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn- seconds-from-now-to-date [secs]
  (-> (Instant/now) (.plusSeconds secs) (Date/from)))

(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token] :as body} :body}]
  (-> {:token access_token
       :extra-data (dissoc body
                           :access_token :expires_in
                           :refresh_token :id_token)}
      (cond-> expires_in (assoc :expires (-> (coerce-to-int expires_in)
                                             (seconds-from-now-to-date)))
              refresh_token (assoc :refresh-token refresh_token)
              id_token (assoc :id-token id_token))))

(defn- get-authorization-code [request]
  (get-in request [:query-params "code"]))

(defn- get-code-verifier [request]
  (get-in request [:session ::code-verifier]))

(defn- request-params [{:keys [pkce?] :as profile} request]
  (-> {:grant_type    "authorization_code"
       :code          (get-authorization-code request)
       :redirect_uri  (redirect-uri profile request)}
      (cond-> pkce? (assoc :code_verifier (get-code-verifier request)))))

(defn- add-header-credentials [opts id secret]
  (assoc opts :basic-auth [id secret]))

(defn- add-form-credentials [opts id secret]
  (assoc opts :form-params (-> (:form-params opts)
                               (merge {:client_id     id
                                       :client_secret secret}))))

(defn- access-token-http-options
  [{:keys [access-token-uri client-id client-secret basic-auth?]
    :or   {basic-auth? false}}
   form-params]
  (let [opts {:method      :post
              :url         access-token-uri
              :accept      :json
              :as          :json
              :form-params form-params}]
    (if basic-auth?
      (add-header-credentials opts client-id client-secret)
      (add-form-credentials   opts client-id client-secret))))

(defn- get-access-token
  ([profile request]
   (-> (access-token-http-options profile (request-params profile request))
       http/request
       (format-access-token)))
  ([profile request respond raise]
   (http/request
    (-> (access-token-http-options profile
                                   (request-params profile request))
        (assoc :async? true))
    (comp respond format-access-token)
    raise)))

(defn state-mismatch-handler
  ([_]
   {:status  400
    :headers {"Content-Type" "text/plain; charset=utf-8"}
    :body    "OAuth2 error: state mismatch"})
  ([request respond _]
   (respond (state-mismatch-handler request))))

(defn no-auth-code-handler
  ([_]
   {:status  400
    :headers {"Content-Type" "text/plain; charset=utf-8"}
    :body    "OAuth2 error: no authorization code"})
  ([request respond _]
   (respond (no-auth-code-handler request))))

(defn- redirect-response [{:keys [id landing-uri]} session access-token]
  (-> (resp/redirect landing-uri)
      (assoc :session (-> session
                          (assoc-in [::access-tokens id] access-token)
                          (dissoc ::state ::code-verifier)))))

(defn- make-redirect-handler
  [{:keys [state-mismatch-handler no-auth-code-handler]
    :or   {state-mismatch-handler state-mismatch-handler
           no-auth-code-handler   no-auth-code-handler}
    :as profile}]
  (fn
    ([{:keys [session] :or {session {}} :as request}]
     (cond
       (not (state-matches? request))
       (state-mismatch-handler request)

       (nil? (get-authorization-code request))
       (no-auth-code-handler request)

       :else
       (let [access-token (get-access-token profile request)]
         (redirect-response profile session access-token))))
    ([{:keys [session] :or {session {}} :as request} respond raise]
     (cond
       (not (state-matches? request))
       (state-mismatch-handler request respond raise)

       (nil? (get-authorization-code request))
       (no-auth-code-handler request respond raise)

       :else
       (get-access-token profile request
                         (fn [token]
                           (respond (redirect-response profile session token)))
                         raise)))))

(defn- expired-access-tokens
  [access-tokens]
  (let [now (Date.)]
    (for [[profile-key {:keys [expires refresh-token]}] access-tokens
          :when (and expires refresh-token (.before expires now))]
      {:profile-key profile-key :refresh-token refresh-token})))

(defn- update-tokens
  [access-tokens [profile-key maybe-grant]]
  (if maybe-grant
    ;; `update ... merge` to properly handle case where authorization server
    ;; does not update the refresh token after use and we should re-use the
    ;; existing refresh token
    (update access-tokens profile-key merge maybe-grant)
    (dissoc access-tokens profile-key)))

(def socket-timeout 60000)

(defn- refresh-one-token
  ([profile refresh-token]
   (-> (access-token-http-options
        profile
        {:grant_type "refresh_token" :refresh_token refresh-token})
       (assoc :socket-timeout socket-timeout)
       http/request
       format-access-token))
  ([profile refresh-token respond raise]
   (-> (access-token-http-options
        profile
        {:grant_type "refresh_token"
         :refresh_token refresh-token})
       (assoc :async? true
              :socket-timeout socket-timeout)
       (http/request (comp respond format-access-token) raise))))

(defn- valid-token? [token]
  (and token (string? token) (not (str/blank? token))))

(defn- refresh-all-tokens
  ([profiles access-tokens]
   (let [refresh-results
         (for [{:keys [profile-key refresh-token]} (expired-access-tokens access-tokens)
               :let [profile (profile-key profiles)]
               :when (and profile (valid-token? refresh-token))]
           [profile-key
            (try (refresh-one-token profile refresh-token)
                 (catch clojure.lang.ExceptionInfo _
                   nil))])]
     (reduce update-tokens access-tokens refresh-results)))
  ([profiles access-tokens respond]
   ;; strategy: launch all requests concurrently, keeping track of completed
   ;; requests in `results`. When all requests have finished, respond.
   (let [expired (expired-access-tokens access-tokens)
         total (count expired)
         results (atom {})  ;; map from profile-key to result
         respond-when-done! #(when (= (count @results) total)
                               (respond (reduce update-tokens
                                                access-tokens @results)))]
     (if (zero? total)
       (respond access-tokens)
       (doseq [{:keys [profile-key refresh-token]} expired
               :let [profile (profile-key profiles)]
               :when (and profile (valid-token? refresh-token))]
         (refresh-one-token profile refresh-token
                            (fn [refresh-result]
                              (swap! results assoc profile-key refresh-result)
                              (respond-when-done!))
                            (fn [_]
                              (swap! results assoc profile-key nil)
                              (respond-when-done!))))))))

(defn- assoc-access-tokens-in-request [request tokens]
  (if tokens
    (assoc request :oauth2/access-tokens tokens)
    request))

(defn- assoc-access-tokens-in-response
  [response tokens]
  (if tokens
    (assoc-in response [:session ::access-tokens] tokens)
    response))

(defn- parse-redirect-url [{:keys [redirect-uri]}]
  (.getPath (java.net.URI. redirect-uri)))

(defn- valid-profile? [{:keys [client-id client-secret]}]
  (and (some? client-id) (some? client-secret)))

(defn wrap-oauth2
  [handler profiles]
  {:pre [(every? valid-profile? (vals profiles))]}
  (let [id-profiles  (for [[k v] profiles] (assoc v :id k))
        launches  (into {} (map (juxt :launch-uri identity)) id-profiles)
        redirects (into {} (map (juxt parse-redirect-url identity)) id-profiles)]
    (fn
      ([{:keys [uri] :as request}]
       (if-let [profile (launches uri)]
         ((make-launch-handler profile) request)
         (if-let [profile (redirects uri)]
           ((:redirect-handler profile (make-redirect-handler profile)) request)
           (let [access-tokens (get-in request [:session ::access-tokens])
                 refreshed-tokens (refresh-all-tokens profiles access-tokens)]
             (-> request
                 (assoc-access-tokens-in-request refreshed-tokens)
                 handler
                 (assoc-access-tokens-in-response refreshed-tokens))))))
      ([{:keys [uri] :as request} respond raise]
       (if-let [profile (launches uri)]
         ((make-launch-handler profile) request respond raise)
         (if-let [profile (redirects uri)]
           ((:redirect-handler profile (make-redirect-handler profile))
            request respond raise)
           (let [access-tokens (get-in request [:session ::access-tokens])
                 respond (fn [refreshed-tokens]
                           (handler
                            (assoc-access-tokens-in-request
                             request refreshed-tokens)
                            (comp respond
                                  #(assoc-access-tokens-in-response
                                    % refreshed-tokens))
                            raise))]
             (refresh-all-tokens profiles access-tokens respond))))))))
