require 'uri'
require 'net/http'
require "json"
require 'cgi'
require 'base64'
require 'openssl'

# https://developer.twitter.com/en/docs/authentication/guides/log-in-with-twitter

class Twitter
    @client_id
    @client_secret
    @access_token
    @id_token

    def initialize(client_id, client_secret, access_token, access_token_secret, redirect_uri)
        @client_id = client_id
        @client_secret = client_secret
        @access_token = access_token
        @access_token_secret = access_token_secret
        @redirect_uri = redirect_uri
    end

    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    # [注意]uriを作成するたびに，それ用のtokenを作成するため，**このuriを動的なページに組み込まないこと！**
    #      例えば，/twitter/loginに来たユーザーをリダイレクトさせる，といった仕様にし，このuriを直接ページに貼らないこと
    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    def generate_authorize_uri
        time = Time.now
        puts  @access_token_secret

        uri = "https://api.twitter.com/oauth/request_token"

        params = {
            "oauth_callback" => @redirect_uri + "/twitter/callback"
        }

        # これが死ぬほど大変
        oauth_params = generate_oauth_params(uri, "POST", params)

        header = {
            "Authorization" => "OAuth " + NetHttp.objectToString(oauth_params, ",")
        }
        puts header

        response = NetHttp.post(uri, params, header)
        puts response.body
        if NetHttp.valid_json?(response.body) then
            puts response.body
            return "/?failed"
        else
            oauth_token = response.body.split("&").map{|item| item.split("=")}[0][1]
            options = {
                "oauth_token" => oauth_token,
                "redirect_uri" => @redirect_uri
            }
            return "https://api.twitter.com/oauth/authenticate?" + NetHttp.objectToString(options);
        end

    end

    # 取得したcodeをaccess_tokenと交換する．access_tokenは各APIを呼び出すための鍵．
    def get_accesstoken(oauth_token, oauth_verifier)
        puts "------- Exchanging from code to access_token ----------"

        post_data = {
            'oauth_token' => oauth_token,
            'oauth_verifier' => oauth_verifier
        }
        uri = "https://api.twitter.com/oauth/access_token?" + NetHttp.objectToString(post_data)

        oauth_params = generate_oauth_params(uri, "POST", post_data)

        header = {
            "Authorization" => "OAuth " + NetHttp.objectToString(oauth_params, ",")
        }
        puts header

        response = NetHttp.post(uri, {})
        userData = {}
        response = response.body.split("&")
        puts response
        response.each{|item| userData[item.split("=")[0]] = item.split("=")[1]}
        puts userData

        return userData
    end

    # ユーザーのプロファイルを取得する
    def get_verify_credentials(oauth_token, oauth_token_secret)
        puts "------- Getting user info ----------"

        uri = "https://api.twitter.com/1.1/account/verify_credentials.json"

        oauth_params = generate_oauth_params(uri, "GET", {}, oauth_token, oauth_token_secret)

        header = {
            "Authorization" => "OAuth " + NetHttp.objectToString(oauth_params, ",")
        }
        puts header

        response = NetHttp.get(uri, {}, header)
        if NetHttp.valid_json?(response.body) then
            return JSON[response.body]
        else
            puts response.body
            return false
        end
    end

    def generate_oauth_params(uri, method, params = {}, access_token = @access_token, access_token_secret = @access_token_secret)
        oauth_params = {
            "oauth_nonce" => [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..42].join,
            # "oauth_callback" => @redirect_uri + "/twitter/callback",
            "oauth_consumer_key" => @client_id,
            "oauth_token" => access_token,
            "oauth_version" => "1.0",
            "oauth_timestamp" => Time.now.to_i.to_s,
            "oauth_signature_method" => "HMAC-SHA1"
        }

        all_params = params.merge(oauth_params)
        all_params = all_params.sort.to_h
        all_params_str = NetHttp.objectToString(all_params)
        signiture_base = [method, uri, all_params_str].map{|item| NetHttp.escape(item)}.join("&")
        signiture_key = [@client_secret, access_token_secret].map{|item| NetHttp.escape(item)}.join("&")
        sha1 = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, signiture_key, signiture_base)
        oauth_params["oauth_signature"] = [sha1].pack('m').gsub(/\n/, '')
        return oauth_params
    end
end
