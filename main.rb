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
require 'base32'
require 'user_agent_parser'

use Rack::MethodOverride

set :environment, :production

ActiveRecord::Base.configurations = YAML.load_file('database.yml')
ActiveRecord::Base.establish_connection :development

class User < ActiveRecord::Base
  has_many :tmp_users, foreign_key: 'user_id', dependent: :destroy
  has_many :sessions, foreign_key: 'user_id', dependent: :destroy
  has_many :credentials, foreign_key: 'user_id', dependent: :destroy
  has_many :posts, foreign_key: 'user_id', dependent: :destroy
  has_many :hearts, foreign_key: 'user_id', dependent: :destroy
end

class Credential < ActiveRecord::Base
  self.inheritance_column = :_type_disabled
  belongs_to :tmp_users
  belongs_to :users
end

class Post < ActiveRecord::Base
  has_many :hearts, foreign_key: 'post_id', dependent: :destroy
  belongs_to :users
end

class Heart < ActiveRecord::Base
  belongs_to :posts
  belongs_to :users
end

class TmpUser < ActiveRecord::Base
  has_many :credentials, foreign_key: 'tmp_user_id', dependent: :nullify
  belongs_to :users
end

class Session < ActiveRecord::Base
  belongs_to :users
end

set :sessions,
    secret: 'xxx'

$view_maximum = 3

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

if File.exist?('credential/github.yml')
  @credential = YAML.load_file('credential/github.yml')
  $g = Github.new(@credential['client_id'], @credential['secret'], $redirect_uri)
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
  l = Heart.find_by(user_id: @user_info.id, post_id: params[:id])
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

  obj = { status: 'success', pressed: pressed, num: Heart.where(post_id: params[:id]).length }
  erb obj.to_json, layout: false
end

get '/' do
  redirect '/' if !params[:since].nil? && !params[:from].nil?
  @user_info = SessionManager.login(session)
  @posts = if !params[:since].nil?
    Post.where(reply_to: nil).where('posted_at < ?', Time.parse(params[:since])).order(posted_at: 'desc').limit($view_maximum)
  elsif !params[:from].nil?
    @rev_order = true
    Post.where(reply_to: nil).where('posted_at > ?', Time.parse(params[:from])).order(posted_at: 'desc').last($view_maximum)
  else
    Post.where(reply_to: nil).order(posted_at: 'desc').limit($view_maximum)
  end
  unless @posts.length.zero?
    @next_button = @posts[0].id != Post.where(reply_to: nil).order(posted_at: 'desc').limit(1)[0].id
    @prev_button = @posts.last(1)[0].id != Post.where(reply_to: nil).order(posted_at: 'desc').last(1)[0].id
  end
  puts @user_info
  puts @user_info.nil?
  erb :index
end

get '/post/new' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  erb :newPost
end

delete '/post' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  post = Post.find_by(id: params[:id].to_i)
  redirect "/?failed=true" if post.nil? || post.user_id != @user_info.id
  post.destroy
  redirect '/'
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
  @posts = Post.where(user_id: @target_user.id, reply_to: nil) unless @target_user.nil?
  puts @user_info
  puts @user_info.nil?
  erb :index
end

get '/login' do
  @user_info = SessionManager.login(session)
  @is_valid_session = SessionManager.is_valid_session?(session)
  redirect '/?loged_in=true' unless @user_info.nil?
  redirect '/login/twofactor' if @is_valid_session == false
  @incorrectFlag = params[:incorrect]
  erb :login
end

get '/login/twofactor' do
  @user_info = SessionManager.login(session)
  @is_valid_session = SessionManager.is_valid_session?(session)
  redirect '/?loged_in=true' unless @user_info.nil?
  redirect '/?logged_in=true' if @is_valid_session == true
  erb :challenge2fa
end

post '/login/twofactor' do
  @user_info = SessionManager.login(session, true)
  credential = Credential.find_by(user_id: @user_info.id, type: 'two_factor')
  tfa = TwoFactorAuth.new(credential.token)
  token = tfa.TOTP
  if token.to_s == params[:confirm_num]
    SessionManager.to_valid(session)
    redirect '/?logged_in=true'
  else
    redirect '/login/twofactor?failed=true'
  end
end

post '/login' do
  token = SessionManager.email(params[:email], params[:password], request.ip, request.env['HTTP_USER_AGENT'])
  redirect '/login?incorrect=true' if token.nil?
  session[:token] = token
  redirect '/login/twofactor' if Session.find_by(token: token).is_valid.zero?
  redirect '/?logged_in=true'
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

delete '/account' do
  u = SessionManager.login(session)
  redirect '/login' if u.nil?
  u.destroy
  redirect '/goodbye'
end

get '/account/delete' do
  u = SessionManager.login(session)
  redirect '/login' if u.nil?
  erb :deleteAccount
end

get '/goodbye' do
  erb :goodbye
end

get '/account/new' do
  @user_info = SessionManager.login(session, true)
  redirect '/?loged_in=true' unless @user_info.nil?
  @incorrectPassword = params[:check_password]
  erb :newAccount
end

post '/account/new' do
  @user_info = SessionManager.login(session)
  logged_in = !@user_info.nil?
  if params[:password] != params[:password_confirm] || params[:password].length <= 0
    redirect '/account/new?check_password=true'
  end

  # ??????????????????????????????????????????????????????
  credential = Credential.where(type: 'email', uid: params[:email]).where.not(user_id: nil)
  puts credential.length
  redirect "#{logged_in ? '/settings/login-method/add' : '/account/new'}?account_exists=true" if credential.length > 0

  credentials = Credential.where(type: 'email', uid: params[:email]).where.not(tmp_user_id: nil)
  credentials.each do |credential|
    puts 'tring to del'
    credential.destroy
  end

  session[:email] = params[:email]
  tmpUser = SessionManager.newTmpUser(@user_info)
  SessionManager.addEmailCredential(params[:email], params[:password], tmpUser.id)
  puts tmpUser.id
  title = @user_info.nil? ? '??????????????????????????????' : '?????????????????????????????????'
  action = @user_info.nil? ? '????????????????????????' : '??????????????????????????????'
  thanks_message = @user_info.nil? ? '??????????????????????????????????????????????????????' : '????????????????????????????????????'
  $goMailer.sendGmail($goMailerCredential, params[:email], "Kicha: #{title}",
                      "#{thanks_message}\n???????????????????????????????????????#{action}???????????????????????????\n\nhttp://localhost:4949/account/new/#{tmpUser.id}\n\n??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????")
  redirect '/account/new/email-sent'
end

get '/account/new/email-sent' do
  redirect '/account/new' if session[:email].nil?
  @email = session[:email]
  session[:email] = nil
  erb :newAccountEmailSent
end

get '/account/new/:id' do
  # ??????????????????????????????????????????????????????
  @tmpuser = TmpUser.find_by(id: params[:id])
  if @tmpuser.nil? || (@tmpuser.expired_at - Time.now) < 0
    @errorTitle = '?????????ID??????'
    @errorDescription = '???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????'
    @suggestAcountCreation = true
    erb :loginError
  else
    @add_email = !@tmpuser.user_id.nil?
    erb :newAccountDetails
  end
end

post '/account/new/:id' do
  tmpuser = TmpUser.find_by(id: params[:id])
  puts tmpuser
  if tmpuser.nil?
    redirect '/account/new/' + params[:id]
  elsif tmpuser.user_id.nil?
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
  else
    c = Credential.find_by(tmp_user_id: params[:id])
    c.user_id = tmpuser.user_id
    c.save
    tmpuser.destroy
    erb :emailVerified
  end
end

get '/settings/login-method/add' do
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

get '/github/login' do
  redirect $g.generate_authorize_uri
end

get '/github/callback' do
  puts params[:code]
  @result = $g.get_accesstoken(params[:code])
  @user_info = $g.get_user_info(@result['access_token'])
  if @user_info != false
    redirect SessionManager.socialLoginRedirectTo(session, 'github', @user_info['id'], @user_info['login'],
                                                  @user_info['avatar_url'], request.ip, request.env['HTTP_USER_AGENT'])
  else
    redirect '/?error'
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
  @session_id = session[:token]
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  @two_fa_set = !Credential.find_by(type: 'two_factor', user_id: @user_info.id).nil?
  @sessions = Session.where(user_id: @user_info.id).order(last_used_at: 'DESC')
  @credentials = Credential.where(user_id: @user_info.id).where.not(type: 'two_factor')
  erb :settings
end

delete '/session' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  puts params[:session_id]
  puts @user_info.id
  target_session = Session.find_by(id: params[:session_id], user_id: @user_info.id)
  puts target_session
  redirect '/settings?failed=true' if target_session.nil?
  target_session.destroy
  redirect '/settings?saved=true'
end

delete '/credential' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  credential = Credential.find_by(id: params[:credential_id], user_id: @user_info.id)
  credentials = Credential.where(user_id: @user_info.id).where.not(type: 'two_factor')
  redirect '/settings?failed=true' if credential.nil? || credentials.length <= 1
  credential.destroy
  redirect '/settings?saved=true'
end

get '/settings/2fa' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  credential = Credential.find_by(type: 'two_factor', user_id: @user_info.id)
  redirect '/settings/2fa/modify' unless credential.nil?
  if !credential.nil?
    token = c.token
  else
    @secret_key = Base32.encode([*'A'..'Z', *0..9].sample(10).join)
    puts 'test: ' + @secret_key
    tfa = TwoFactorAuth.new(@secret_key)
    token = tfa.TOTP
    puts 'aa'
    puts token
  end
  service_name = 'Kicha'
  qr = RQRCode::QRCode.new("otpauth://totp/#{service_name}:#{@user_info.display_id}?secret=#{@secret_key}&issuer=#{service_name}")
  @svg = qr.as_svg(
    color: '000',
    shape_rendering: 'crispEdges',
    module_size: 6,
    use_path: true
  )
  erb :start2fa
end

delete '/settings/2fa' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  credentials = Credential.where(type: 'two_factor', user_id: @user_info.id)
  redirect '/settings/2fa' if credentials.length <= 0
  credentials.each { |c| c.destroy }
  redirect '/settings/2fa?deleted=true'
end

post '/settings/2fa' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  credential = Credential.find_by(type: 'two_factor', user_id: @user_info.id)
  redirect '/settings/2fa/modify' unless credential.nil?
  secret_key = params[:sec_key] # [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
  tfa = TwoFactorAuth.new(secret_key)
  token = tfa.TOTP
  puts 'confirm----------------'
  puts token.to_s
  puts params[:confirm_num]
  if token.to_s == params[:confirm_num]
    SessionManager.add_2fa_credential(secret_key, @user_info.id)
    redirect '/settings?saved=true'
  else
    redirect '/settings/2fa?failed=true'
  end
end

get '/settings/2fa/modify' do
  @user_info = SessionManager.login(session)
  redirect '/login' if @user_info.nil?
  credential = Credential.find_by(type: 'two_factor', user_id: @user_info.id)
  redirect '/settings/2fa' if credential.nil?
  erb :reset2fa
end
