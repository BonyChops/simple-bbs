require "sinatra"
require "sinatra/reloader"
require "active_record"
require "digest/md5"
require "./controller/functions"
require "./oauth/line"
require "./oauth/twitter"
require "./oauth/discord"
require "./oauth/github"

if(File.exist?('credential/general.yml')) then
    credential = YAML.load_file("credential/general.yml")
    $redirect_uri = credential["redirect_uri"]
end

if(File.exist?('credential/line.yml')) then
    @credential = YAML.load_file("credential/line.yml")
    $l = Line.new(@credential["client_id"], @credential["secret"],  $redirect_uri)
end

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

get "/" do
    @userInfo = SessionManager.login(session)
    @posts = Post.all.order(posted_at: "desc")
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
    p.save
    redirect "/?posted=true"
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
    if @userInfo != nil
        redirect "/?loged_in=true"
    end
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
