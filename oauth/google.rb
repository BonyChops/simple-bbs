require 'uri'
require 'net/http'
require "json"
require 'cgi'
require 'base64'
require 'openssl'
require "./oauth/http"
require "time"

# https://developer.twitter.com/en/docs/authentication/guides/log-in-with-twitter

class Google
    @client_id
    @client_secret
    @access_token
    @id_token

    def initialize(client_id, client_secret, redirect_uri, custom = false)
        @client_id = client_id
        @client_secret = client_secret
        @redirect_uri = custom ? redirect_uri : redirect_uri + "/google/callback"
    end

    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    # [注意]uriを作成するたびに，それ用のtokenを作成するため，**このuriを動的なページに組み込まないこと！**
    #      例えば，/twitter/loginに来たユーザーをリダイレクトさせる，といった仕様にし，このuriを直接ページに貼らないこと
    # ユーザーに認証画面へ移動してもらうためのURLを作成する．
    def generate_authorize_uri(scope = [], access_type = "online")
        options = {
            "client_id" => @client_id,
            "redirect_uri" => @redirect_uri,
            "access_type" => access_type,
            "scope" => (["openid", "https://www.googleapis.com/auth/userinfo.profile"] + scope).join(" "),
            "response_type" => "code"
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + NetHttp.objectToString(options)
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
        uri = "https://oauth2.googleapis.com/token"

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

        uri = "https://www.googleapis.com/oauth2/v1/userinfo"

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

    def exchange_token(refresh_token)
        puts "------- Exchanging from code to access_token ----------"

        post_data = {
            "client_id" => @client_id,
            "client_secret" => @client_secret,
            "grant_type" => "refresh_token",
            "refresh_token" => refresh_token,
        }
        puts post_data
        uri = "https://oauth2.googleapis.com/token"

        response = NetHttp.post(uri, post_data)
        if NetHttp.valid_json?(response.body) then
            puts JSON[response.body]
            return JSON[response.body]
        else
            puts response.body
            return false
        end
    end

    def sendGmail(g_credential, to, subject, body, from = "me")
        mimeData = [
            "To: #{to}",
            "Subject: =?utf-8?B?#{Base64.encode64(subject).gsub(/\n/, "")}?=",
            "Content-Type: text/plain; charset=utf-8\n",
            "\n#{body}"
        ]
        puts Base64.urlsafe_encode64(subject)
        puts "------- Exchanging from code to access_token ----------"

        post_data = {
            "raw" => Base64.urlsafe_encode64(mimeData.join("\n"))
            # 'payload': {'mimeType': 'text/html'}
        }

        puts post_data
        uri = "https://www.googleapis.com/gmail/v1/users/#{from}/messages/send"

        header = {
            "Authorization" => "Bearer " + g_credential.get_accesstoken,
            "Content-Type" => "application/json"
        }

        response = NetHttp.post(uri, post_data, header, true)
        if NetHttp.valid_json?(response.body) then
            puts JSON[response.body]
            return JSON[response.body]
        else
            puts response.body
            return false
        end
    end
end

class GoogleCredential
    def initialize(obj, googleClass)
        puts obj
        @access_token = obj["access_token"]
        @refresh_token = obj["refresh_token"]
        @expired_at = Time.parse(obj["expires_in"])
        @g = googleClass
    end

    def get_accesstoken
        if(@expired_at < Time.now)
            # 更新が必要
            puts "Attempt to regenerate token"
            obj = @g.exchange_token(@refresh_token)
            obj["expires_in"] = Time.now + obj["expires_in"]
            @access_token = obj["access_token"]
            @expired_at = obj["expires_in"]
            obj["refresh_token"] = @refresh_token
            File.open("./credential/googleMailerToken.json", mode = "w"){|f|
                f.write(JSON.pretty_generate(obj))  # ファイルに書き込む
            }
        end
        return @access_token
    end
end
