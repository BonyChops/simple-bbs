require 'uri'
require 'net/http'
require "json"
require 'cgi'
require 'base64'
require 'openssl'

# https://developer.twitter.com/en/docs/authentication/guides/log-in-with-twitter

class Discord
    @client_id
    @client_secret
    @access_token
    @id_token

    def initialize(client_id, client_secret, redirect_uri)
        @client_id = client_id
        @client_secret = client_secret
        @redirect_uri = redirect_uri + "/discord/callback"
    end

    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    # [注意]uriを作成するたびに，それ用のtokenを作成するため，**このuriを動的なページに組み込まないこと！**
    #      例えば，/twitter/loginに来たユーザーをリダイレクトさせる，といった仕様にし，このuriを直接ページに貼らないこと
    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    def generate_authorize_uri
        options = {
            "client_id" => @client_id,
            "redirect_uri" => @redirect_uri,
            "scope" => "identify",
            "response_type" => "code"
        }
        return "https://discord.com/api/oauth2/authorize?" + NetHttp.objectToString(options);
        # https://discord.com/api/oauth2/authorize?client_id=xxx&redirect_uri=http%3A%2F%2Flocalhost%3A4649%2Fdiscord%2Fredirect&response_type=code&scope=identify

    end

    # 取得したcodeをaccess_tokenと交換する．access_tokenは各APIを呼び出すための鍵．

    def get_accesstoken(code)
        puts "------- Exchanging from code to access_token ----------"

        post_data = {
            "client_id" => @client_id,
            "client_secret" => @client_secret,
            "grant_type" => "authorization_code",
            "code" => code,
            'redirect_uri' => @redirect_uri
        }
        puts post_data
        uri = "https://discord.com/api/oauth2/token"

        response = NetHttp.post(uri, post_data)
        if NetHttp.valid_json?(response.body) then
            puts JSON[response.body]
            return JSON[response.body]
        else
            puts response.body
            return false
        end
    end


    # ユーザーのプロファイルを取得する
    def get_user_info(access_token)
        puts "------- Getting user info ----------"

        uri = "https://discord.com/api/oauth2/@me"

        header = {
            "Authorization" => "Bearer " + access_token
        }

        response = NetHttp.get(uri, {}, header)
        if NetHttp.valid_json?(response.body) then
            puts JSON[response.body]
            return JSON[response.body]
        else
            puts response.body
            return false
        end
    end
    def get_avatar_uri(user_id, avatar_hash)
        return "https://cdn.discordapp.com/avatars/#{user_id}/#{avatar_hash}.png"
    end
end
