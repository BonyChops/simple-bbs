require 'uri'
require 'net/http'
require "json"
require 'cgi'
require "./oauth/http"


class Github
    @client_id
    @client_secret

    def initialize(client_id, client_secret, redirect_uri)
        @client_id = client_id
        @client_secret = client_secret
        @redirect_uri = redirect_uri
    end

    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    def generate_authorize_uri
        options = {
            "client_id" => @client_id,
            # "scope" => "profile openid"
        }
         # options = ["response=code", "client_id=unko", ...]
        return "https://github.com/login/oauth/authorize?" + options.map{|key, value| "#{CGI.escape(key)}=#{CGI.escape(value)}"}.join("&");
    end

    # 取得したcodeをaccess_tokenと交換する．access_tokenは各APIを呼び出すための鍵．
    def get_accesstoken(code)
        puts "------- Exchanging from code to access_token ----------"
        post_data = {
            'code' => code,
            # 'redirect_uri' => @redirect_uri + "/line/callback",
            'client_id' => @client_id,
            'client_secret' => @client_secret
        }

        response = NetHttp.post("https://github.com/login/oauth/access_token", post_data)

        puts response.body
        userData = {}
        response = response.body.split("&")
        response.each{|item| userData[item.split("=")[0]] = item.split("=")[1]}
        puts userData

        return userData
    end

    # アクセストークンが本当に正規の場所から発行されているかを検証する．また，このときにユーザー情報を取得できる．
    def get_user_info(access_token)
        puts "------- Getting user info ----------"


        header = {
            "Authorization" => "token " + access_token
        }

        response = NetHttp.get("https://api.github.com/user", {}, header)

        puts response.body
        if JSON[response.body]["error"] == nil then
            return JSON[response.body]
        else
            return false
        end
    end


end
