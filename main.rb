require "sinatra"
require "sinatra/reloader"
require "active_record"
require "digest/md5"
require "./controller/functions"
require "./oauth/line"
require "./oauth/twitter"
require "./oauth/discord"
require "./oauth/github"
require "./oauth/google"
require "rqrcode"


use Rack::MethodOverride

set :environment , :production

ActiveRecord::Base.configurations = YAML.load_file("database.yml")
ActiveRecord::Base.establish_connection :development

class User < ActiveRecord::Base
end

class Credential < ActiveRecord::Base
    self.inheritance_column = :_type_disabled
    belongs_to :TmpUser
end

class Post < ActiveRecord::Base
end

class Heart < ActiveRecord::Base
end

class Setting < ActiveRecord::Base
end

class TmpUser < ActiveRecord::Base
    has_many :credentials, dependent: :nullify
end

class Session < ActiveRecord::Base
end

set :sessions,
    secret: "xxx"

if(File.exist?('credential/general.yml')) then
    credential = YAML.load_file("credential/general.yml")
    $redirect_uri = credential["redirect_uri"]
end

if(File.exist?('credential/line.yml')) then
    @credential = YAML.load_file("credential/line.yml")
    $l = Line.new(@credential["client_id"], @credential["secret"],  $redirect_uri)
end

if(File.exist?('credential/twitter.yml')) then
    @credential = YAML.load_file("credential/twitter.yml")
    $t = Twitter.new(@credential["client_id"], @credential["secret"], @credential["access_token"], @credential["access_token_secret"], $redirect_uri)
end

if(File.exist?('credential/discord.yml')) then
    @credential = YAML.load_file("credential/discord.yml")
    $d = Discord.new(@credential["client_id"], @credential["secret"], $redirect_uri)
end

if(File.exist?('credential/google.json')) then
    @credential = JSON.parse(File.read('credential/google.json'))
    $go = Google.new(@credential["web"]["client_id"], @credential["web"]["client_secret"], $redirect_uri)
end

@credential = JSON.parse(File.read('credential/googleMailer.json'))
$goMailer = Google.new(@credential["installed"]["client_id"], @credential["installed"]["client_secret"], @credential["installed"]["redirect_uris"][0], true)
@credential = JSON.parse(File.read('credential/googleMailerToken.json'))
$goMailerCredential = GoogleCredential.new(@credential, $goMailer)

post "/api/post/:id/like/toggle" do
    @userInfo = SessionManager.login(session)
    l = Heart.find_by(user_id: @userInfo.id)
    if l == nil
        l = Heart.new
        l.user_id = @userInfo.id
        l.post_id = params[:id]
        l.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
        l.created_at = Time.now
        l.save
        pressed = true
    else
        l.destroy
        pressed = false
    end

    obj = {status: "success", pressed: pressed}
    erb obj.to_json, :layout => false
end

get "/" do
    @userInfo = SessionManager.login(session)
    @posts = Post.where(reply_to: nil).order(posted_at: "desc")
    puts @userInfo
    puts @userInfo == nil
    erb :index
end

get "/post/new" do
    @userInfo = SessionManager.login(session)
    redirect "/login" if @userInfo == nil
    erb :newPost
end

post "/post/new" do
    @userInfo = SessionManager.login(session)
    redirect "/login" if @userInfo == nil
    p = Post.new
    p.id = [*0..9].shuffle[0..18].join
    p.user_id = @userInfo.id
    p.posted_at = Time.now
    p.content = params[:content]
    p.reply_to = params[:reply_to] if params[:reply_to] != nil
    p.save
    if params[:reply_to] == nil
        redirect "/?posted=true"
    else
        redirect "/post/#{params[:reply_to]}?posted=true"
    end
end

get "/post/:id" do
    @targetPost = Post.find_by(id: params[:id])
    @userInfo = SessionManager.login(session)
    @posts = Post.where(reply_to: params[:id])
    puts @userInfo
    puts @userInfo == nil
    erb :index
end


get "/login" do
    @userInfo = SessionManager.login(session)
    if @userInfo != nil
        redirect "/?loged_in=true"
    end
    @incorrectFlag = params[:incorrect]
    erb :login
end

post "/login" do
    token = SessionManager.email(params[:email], params[:password], request.ip, request.env['HTTP_USER_AGENT'])
    redirect "/login?incorrect=true" if token == nil
    session[:token] = token
    redirect "/?logged_in"
end

get "/logout" do
    SessionManager.logout(session)
    session[:token] = nil
    redirect "/?logged_out=true"
end

get "/account/new" do
    @userInfo = SessionManager.login(session)
    redirect "/?loged_in=true" if @userInfo != nil
    @incorrectPassword = params[:check_password]
    erb :newAccount
end

post "/account/new" do
    if params[:password] != params[:password_confirm] || params[:password].length <= 0
        redirect "/account/new?check_password=true"
    end

    #実在するアカウントがないかを確認する
    credential = Credential.where(type: "email", uid: params[:email]).where.not(user_id: nil)
    puts credential.length
    if credential.length > 0
        redirect "/account/new?account_exists=true"
    end

    credentials = Credential.where(type: "email", uid: params[:email]).where.not(tmp_user_id: nil)
    credentials.each do |credential|
        puts "tring to del"
        credential.destroy
    end

    session[:email] = params[:email]
    tmpUser = SessionManager.newTmpUser
    SessionManager.addEmailCredential(params[:email], params[:password], tmpUser.id)
    puts tmpUser.id
    $goMailer.sendGmail($goMailerCredential, params[:email], "Kicha: さあ，はじめましょう", "アカウント作成ありがとうございます！\n下記のリンクをクリックし，アカウント作成を完了させましょう\n\nhttp://localhost:4949/account/new/#{tmpUser.id}\n\n※このメールに心当たりない場合は，お手数ですがこのメールを削除してくださいますようお願いいたします．")
    redirect "/account/new/email-sent"
end

get "/account/new/email-sent" do
    if session[:email] == nil
        redirect "/account/new"
    end
    @email = session[:email]
    session[:email] = nil
    erb :newAccountEmailSent
end

get "/account/new/:id" do
    #実在するアカウントがないかを確認する
    tmpuser = TmpUser.where(id: params[:id])
    if tmpuser.length <= 0 || (tmpuser[0].expired_at - Time.now) < 0
        @errorTitle = "無効なIDです"
        @errorDescription = "メールよりこのメッセージを確認している場合，有効期限がきれている可能性があります．もう一度アカウント作成を行ってください．"
        @suggestAcountCreation = true
        erb :loginError
    else
        erb :newAccountDetails
    end
end

post "/account/new/:id" do
    tmpuser = TmpUser.where(id: params[:id])
    puts tmpuser
    if tmpuser.length <= 0
        redirect "/account/new/" + params[:id]
    else
        u = User.new
        u.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
        u.status = params[:status]
        u.display_name = params[:display_name]
        u.display_id = params[:display_id]
        u.save
        c = Credential.find_by(tmp_user_id: params[:id])
        tmpuser[0].destroy
        # c.tmp_user_id = nil
        c.user_id = u.id
        c.save
        token = SessionManager.admin_start(u.id, request.ip, request.env['HTTP_USER_AGENT'])
        session[:token] = token
        redirect "/"
    end
end

get "/line/login" do
    redirect $l.generate_authorize_uri
end

get "/line/callback" do
    puts params[:code]
    @result = $l.get_accesstoken(params[:code])
    @userInfo = $l.get_user_info(@result["id_token"])
    redirect SessionManager.socialLoginRedirectTo(session, "line", @userInfo["sub"], @userInfo["name"], @userInfo["picture"], request.ip, request.env['HTTP_USER_AGENT'] )
end

get "/line/login" do
    redirect $l.generate_authorize_uri
end

get "/line/callback" do
    puts params[:code]
    @result = $l.get_accesstoken(params[:code])
    @userInfo = $l.get_user_info(@result["id_token"])
    redirect SessionManager.socialLoginRedirectTo(session, "line", @userInfo["sub"], @userInfo["name"], @userInfo["picture"], request.ip, request.env['HTTP_USER_AGENT'] )
end

get "/twitter/login" do
    redirect $t.generate_authorize_uri
end

get "/twitter/callback" do
    @result = $t.get_accesstoken(params[:oauth_token], params[:oauth_verifier])
    @userInfo = $t.get_verify_credentials(@result["oauth_token"], @result["oauth_token_secret"])
    if @userInfo != false
        redirect SessionManager.socialLoginRedirectTo(session, "twitter", @userInfo["id_str"], @userInfo["name"],@userInfo["profile_image_url_https"].gsub(/_normal/, ''), request.ip, request.env['HTTP_USER_AGENT'])
    else
        redirect "/?error"
    end
end

get "/discord/login" do
    redirect $d.generate_authorize_uri
end


get "/discord/callback" do
    @result = $d.get_accesstoken(params[:code])
    @clientData = $d.get_user_info(@result["access_token"])

    if @clientData != false then
        @userInfo = @clientData["user"]
        redirect SessionManager.socialLoginRedirectTo(session, "discord", @userInfo["id"], @userInfo["username"], $d.get_avatar_uri(@userInfo["id"], @userInfo["avatar"]), request.ip, request.env['HTTP_USER_AGENT'])
    else
        redirect "/"
    end
end

get "/google/login" do
    puts $go.generate_authorize_uri
    redirect $go.generate_authorize_uri
end

get "/google/login/warn" do
    erb :googleLoginWarning
end

get "/google/callback" do
    puts params[:code]
    $go.generate_authorize_uri(["https://mail.google.com/", "https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.compose", "https://www.googleapis.com/auth/gmail.send"])
    @result = $go.get_accesstoken(params[:code])
    puts @result
    @userInfo = $go.get_user_info(@result["access_token"])
    pp @userInfo
    if @userInfo != false
        redirect SessionManager.socialLoginRedirectTo(session, "google", @userInfo["id"], @userInfo["name"], @userInfo["picture"], request.ip, request.env['HTTP_USER_AGENT'])
    else
        redirect "/"
    end
end

get '/settings/2fa' do
    @userInfo = SessionManager.login(session)
    redirect "/login" if @userInfo == nil
    c = Credential.find_by(type: "2fa", user_id: @userInfo.id)
    if c != nil
        token = c.token
    else
        secret_key = "AOHT4WFMAL"
        tfa = TwoFactorAuth.new(secret_key)
        token = tfa.TOTP
        puts "aa"
        puts token
    end
    service_name = "Kicha"
    qr = RQRCode::QRCode.new("otpauth://totp/#{service_name}:contact.bonychops@gmail.com?secret=#{secret_key}&issuer=#{service_name}")
    @svg = qr.as_svg(
        color: "000",
        shape_rendering: "crispEdges",
        module_size: 6,
        use_path: true
    )
    erb :start2fa
end

post "/settings/2fa" do
    secret_key = "AOHT4WFMAL" #[*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
    tfa = TwoFactorAuth.new(secret_key)
    token = tfa.TOTP
    puts"confirm----------------"
    puts token.to_s
    puts params[:confirm_num]
    if(token.to_s == params[:confirm_num])
        redirect "/settings/2fa?success=true"
    else
        redirect "/settings/2fa?failed=true"
    end
end