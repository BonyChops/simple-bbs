# frozen_string_literal: true

require 'sinatra'
require 'sinatra/reloader'
require 'active_record'
require 'digest/md5'
require './controller/functions'
require './oauth/line'
require './oauth/twitter'
require './oauth/discord'
require './oauth/github'
require './oauth/google'
require 'rqrcode'

use Rack::MethodOverride

set :environment, :production

ActiveRecord::Base.configurations = YAML.load_file('database.yml')
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
    secret: 'xxx'

if File.exist?('credential/general.yml')
  credential = YAML.load_file('credential/general.yml')
  $redirect_uri = credential['redirect_uri']
end

if File.exist?('credential/line.yml')
  @credential = YAML.load_file('credential/line.yml')
  $l = Line.new(@credential['client_id'], @credential['secret'], $redirect_uri)
end

if File.exist?('credential/twitter.yml')
  @credential = YAML.load_file('credential/twitter.yml')
  $t = Twitter.new(@credential['client_id'], @credential['secret'], @credential['access_token'],
                   @credential['access_token_secret'], $redirect_uri)
end

if File.exist?('credential/discord.yml')
  @credential = YAML.load_file('credential/discord.yml')
  $d = Discord.new(@credential['client_id'], @credential['secret'], $redirect_uri)
end

if File.exist?('credential/google.json')
  @credential = JSON.parse(File.read('credential/google.json'))
  $go = Google.new(@credential['web']['client_id'], @credential['web']['client_secret'], $redirect_uri)
end

@credential = JSON.parse(File.read('credential/googleMailer.json'))
$goMailer = Google.new(@credential['installed']['client_id'], @credential['installed']['client_secret'],
                       @credential['installed']['redirect_uris'][0], true)
@credential = JSON.parse(File.read('credential/googleMailerToken.json'))
$goMailerCredential = GoogleCredential.new(@credential, $goMailer)

post '/api/post/:id/like/toggle' do
  @user_info = SessionManager.login(session)
  l = Heart.find_by(user_id: @user_info.id)
  if l.nil?
    l = Heart.new
    l.user_id = @user_info.id
    l.post_id = params[:id]
    l.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
    l.created_at = Time.now
    l.save
    pressed = true
  else
    l.destroy
    pressed = false
  end

  obj = { status: 'success', pressed: pressed }
  erb obj.to_json, layout: false
end

get '/' do
  @user_info = SessionManager.login(session)
  @posts = Post.where(reply_to: nil).order(posted_at: 'desc')
  puts @user_info
  puts @user_info.nil?
  erb :index
end

get '/post/new' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  erb :newPost
end

post '/post/new' do
  if params[:content].nil? || params[:content].length <= 0
    redirect '/?post_failed=true'
  else
    @user_info = SessionManager.login(session)
    redirect '/login' if @user_info.nil?
    p = Post.new
    p.id = [*0..9].sample(19).join
    p.user_id = @user_info.id
    p.posted_at = Time.now
    p.content = params[:content]
    p.reply_to = params[:reply_to] unless params[:reply_to].nil?
    p.save
    if params[:reply_to].nil?
      redirect '/?posted=true'
    else
      redirect "/post/#{params[:reply_to]}?posted=true"
    end
  end
end

get '/post/:id' do
  @user_info = SessionManager.login(session)
  @target_post = Post.find_by(id: params[:id])
  @posts = Post.where(reply_to: params[:id])
  puts @user_info
  puts @user_info.nil?
  erb :index
end

get '/user/:id' do
  @user_info = SessionManager.login(session)
  @target_user = User.find_by(display_id: params[:id])
  @disable_post_box = true
  @posts = Post.where(user_id: @target_user.id) unless @target_user.nil?
  puts @user_info
  puts @user_info.nil?
  erb :index
end

get '/login' do
  @user_info = SessionManager.login(session)
  redirect '/?loged_in=true' unless @user_info.nil?
  @incorrectFlag = params[:incorrect]
  erb :login
end

post '/login' do
  token = SessionManager.email(params[:email], params[:password], request.ip, request.env['HTTP_USER_AGENT'])
  redirect '/login?incorrect=true' if token.nil?
  session[:token] = token
  redirect '/?logged_in'
end

get '/logout' do
  SessionManager.logout(session)
  session[:token] = nil
  redirect '/?logged_out=true'
end

put '/account' do
  u = SessionManager.login(session)
  redirect '/login' if u.nil?
  errors = []
  errors.push('status_too_long') if params[:status].length > 512
  errors.push('invalid_display_id') if params[:display_id].match(/^[a-zA-Z0-9\-_]{1,18}$/).nil?
  if params[:display_id] != u.display_id && !User.find_by(display_id: params[:display_id]).nil?
    errors.push('id_already_exists')
  end
  errors.push('display_name_too_long') if params[:display_name].length > 64
  errors.push('icon_missmatch') if params[:icon_uri].match(%r{^/}).nil? && Credential.find_by(
    icon_uri: params[:icon_uri], user_id: u.id
  ).nil?
  if errors.length <= 0
    u.status = params[:status]
    u.display_name = params[:display_name]
    u.display_id = params[:display_id]
    u.icon_uri = params[:icon_uri]
    u.save
  end
  redirect "/settings?#{errors.length <= 0 ? 'saved=true' : errors.map { |item| "#{item}=true" }.join('&')}"
end

get '/account/new' do
  @user_info = SessionManager.login(session)
  redirect '/?loged_in=true' unless @user_info.nil?
  @incorrectPassword = params[:check_password]
  erb :newAccount
end

post '/account/new' do
  if params[:password] != params[:password_confirm] || params[:password].length <= 0
    redirect '/account/new?check_password=true'
  end

  # 実在するアカウントがないかを確認する
  credential = Credential.where(type: 'email', uid: params[:email]).where.not(user_id: nil)
  puts credential.length
  redirect '/account/new?account_exists=true' if credential.length > 0

  credentials = Credential.where(type: 'email', uid: params[:email]).where.not(tmp_user_id: nil)
  credentials.each do |credential|
    puts 'tring to del'
    credential.destroy
  end

  session[:email] = params[:email]
  tmpUser = SessionManager.newTmpUser
  SessionManager.addEmailCredential(params[:email], params[:password], tmpUser.id)
  puts tmpUser.id
  $goMailer.sendGmail($goMailerCredential, params[:email], 'Kicha: さあ，はじめましょう',
                      "アカウント作成ありがとうございます！\n下記のリンクをクリックし，アカウント作成を完了させましょう\n\nhttp://localhost:4949/account/new/#{tmpUser.id}\n\n※このメールに心当たりない場合は，お手数ですがこのメールを削除してくださいますようお願いいたします．")
  redirect '/account/new/email-sent'
end

get '/account/new/email-sent' do
  redirect '/account/new' if session[:email].nil?
  @email = session[:email]
  session[:email] = nil
  erb :newAccountEmailSent
end

get '/account/new/:id' do
  # 実在するアカウントがないかを確認する
  @tmpuser = TmpUser.find_by(id: params[:id])
  if @tmpuser.nil? || (@tmpuser.expired_at - Time.now) < 0
    @errorTitle = '無効なIDです'
    @errorDescription = 'メールよりこのメッセージを確認している場合，有効期限がきれている可能性があります．もう一度アカウント作成を行ってください．'
    @suggestAcountCreation = true
    erb :loginError
  else
    erb :newAccountDetails
  end
end

post '/account/new/:id' do
  tmpuser = TmpUser.find_by(id: params[:id])
  puts tmpuser
  if tmpuser.nil?
    redirect '/account/new/' + params[:id]
  else
    errors = []
    errors.push('status_too_long') if params[:status].length > 512
    errors.push('invalid_display_id') if params[:display_id].match(/^[a-zA-Z0-9\-_]{1,18}$/).nil?
    errors.push('id_already_exists') unless User.find_by(display_id: params[:display_id]).nil?
    errors.push('display_name_too_long') if params[:display_name].length > 64
    errors.push('icon_missmatch') if params[:icon_uri].nil? || (params[:icon_uri].match(%r{^/}).nil? && Credential.find_by(
      icon_uri: params[:icon_uri], tmp_user_id: params[:id]
    ).nil?)
    if errors.length <= 0
      u = User.new
      u.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
      u.status = params[:status]
      u.display_name = params[:display_name]
      u.display_id = params[:display_id]
      u.icon_uri = params[:icon_uri]
      u.save
      c = Credential.find_by(tmp_user_id: params[:id])
      tmpuser.destroy
      # c.tmp_user_id = nil
      c.user_id = u.id
      c.save
      token = SessionManager.admin_start(u.id, request.ip, request.env['HTTP_USER_AGENT'])
      session[:token] = token
    end
    redirect errors.length <= 0 ? '/' : "/account/new/#{params[:id]}?#{errors.map { |item| "#{item}=true" }.join('&')}"
  end
end

get '/settings/social-account/add' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  erb :addSocialAccount
end


get '/line/login' do
  redirect $l.generate_authorize_uri
end

get '/line/callback' do
  puts params[:code]
  @result = $l.get_accesstoken(params[:code])
  @user_info = $l.get_user_info(@result['id_token'])
  redirect SessionManager.socialLoginRedirectTo(session, 'line', @user_info['sub'], @user_info['name'],
                                                @user_info['picture'], request.ip, request.env['HTTP_USER_AGENT'])
end

get '/line/login' do
  redirect $l.generate_authorize_uri
end

get '/line/callback' do
  puts params[:code]
  @result = $l.get_accesstoken(params[:code])
  @user_info = $l.get_user_info(@result['id_token'])
  redirect SessionManager.socialLoginRedirectTo(session, 'line', @user_info['sub'], @user_info['name'],
                                                @user_info['picture'], request.ip, request.env['HTTP_USER_AGENT'])
end

get '/twitter/login' do
  redirect $t.generate_authorize_uri
end

get '/twitter/callback' do
  @result = $t.get_accesstoken(params[:oauth_token], params[:oauth_verifier])
  @user_info = $t.get_verify_credentials(@result['oauth_token'], @result['oauth_token_secret'])
  if @user_info != false
    redirect SessionManager.socialLoginRedirectTo(session, 'twitter', @user_info['id_str'], @user_info['name'],
                                                  @user_info['profile_image_url_https'].gsub(/_normal/, ''), request.ip, request.env['HTTP_USER_AGENT'])
  else
    redirect '/?error'
  end
end

get '/discord/login' do
  redirect $d.generate_authorize_uri
end

get '/discord/callback' do
  @result = $d.get_accesstoken(params[:code])
  @clientData = $d.get_user_info(@result['access_token'])

  if @clientData != false
    @user_info = @clientData['user']
    redirect SessionManager.socialLoginRedirectTo(session, 'discord', @user_info['id'], @user_info['username'],
                                                  $d.get_avatar_uri(@user_info['id'], @user_info['avatar']), request.ip, request.env['HTTP_USER_AGENT'])
  else
    redirect '/'
  end
end

get '/google/login' do
  puts $go.generate_authorize_uri
  redirect $go.generate_authorize_uri
end

get '/google/login/warn' do
  erb :googleLoginWarning
end

get '/google/callback' do
  puts params[:code]
  $go.generate_authorize_uri(['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.modify',
                              'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.send'])
  @result = $go.get_accesstoken(params[:code])
  puts @result
  @user_info = $go.get_user_info(@result['access_token'])
  pp @user_info
  if @user_info != false
    redirect SessionManager.socialLoginRedirectTo(session, 'google', @user_info['id'], @user_info['name'],
                                                  @user_info['picture'], request.ip, request.env['HTTP_USER_AGENT'])
  else
    redirect '/'
  end
end

get '/settings' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  erb :settings
end

get '/settings/2fa' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  c = Credential.find_by(type: '2fa', user_id: @user_info.id)
  if !c.nil?
    token = c.token
  else
    secret_key = 'AOHT4WFMAL'
    tfa = TwoFactorAuth.new(secret_key)
    token = tfa.TOTP
    puts 'aa'
    puts token
  end
  service_name = 'Kicha'
  qr = RQRCode::QRCode.new("otpauth://totp/#{service_name}:contact.bonychops@gmail.com?secret=#{secret_key}&issuer=#{service_name}")
  @svg = qr.as_svg(
    color: '000',
    shape_rendering: 'crispEdges',
    module_size: 6,
    use_path: true
  )
  erb :start2fa
end

post '/settings/2fa' do
  secret_key = 'AOHT4WFMAL' # [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
  tfa = TwoFactorAuth.new(secret_key)
  token = tfa.TOTP
  puts 'confirm----------------'
  puts token.to_s
  puts params[:confirm_num]
  if token.to_s == params[:confirm_num]
    redirect '/settings/2fa?success=true'
  else
    redirect '/settings/2fa?failed=true'
  end
end
