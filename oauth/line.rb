require 'uri'
require 'net/http'
require "json"
require 'cgi'
require "./oauth/http"

# https://developers.line.biz/ja/docs/line-login/integrate-line-login/

class Line
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
            "response_type" => "code",
            "client_id" => @client_id,
            "redirect_uri" => @redirect_uri + "/line/callback",
            "state" => [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..7].join,
            "scope" => "profile openid"
        }
         # options = ["response=code", "client_id=unko", ...]
        return "https://access.line.me/oauth2/v2.1/authorize?" + options.map{|key, value| "#{CGI.escape(key)}=#{CGI.escape(value)}"}.join("&");
    end

    # 取得したcodeをaccess_tokenと交換する．access_tokenは各APIを呼び出すための鍵．
    def get_accesstoken(code)
        puts "------- Exchanging from code to access_token ----------"
        post_data = {
            'grant_type' => 'authorization_code',
            'code' => code,
            'redirect_uri' => @redirect_uri + "/line/callback",
            'client_id' => @client_id,
            'client_secret' => @client_secret
        }

        response = NetHttp.post("https://api.line.me/oauth2/v2.1/token", post_data)

        puts response.body
        if JSON[response.body]["error"] == nil then
            result = {}
            result["access_token"] = JSON[response.body]["access_token"]
            result["id_token"] = JSON[response.body]["id_token"]
            return result
        else
            return false
        end
    end

    # アクセストークンが本当に正規の場所から発行されているかを検証する．また，このときにユーザー情報を取得できる．
    def get_user_info(id_token)
        puts "------- Verify token ----------"

        post_data = {
            'id_token' => id_token,
            'client_id' => @client_id
        }

        response = NetHttp.post("https://api.line.me/oauth2/v2.1/verify", post_data)

        puts response.body
        if JSON[response.body]["error"] == nil then
            return JSON[response.body]
        else
            return false
        end
    end


end
