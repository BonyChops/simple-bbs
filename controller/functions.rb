require 'base32'
require './oauth/http'

class SessionManager
  def self.login(session)
    token = session[:token]
    return token if token.nil?

    session = Session.find_by(token: token)
    return nil if session.nil?
    session.last_used_at = Time.now
    session.save

    User.find(session.user_id)
  end

  def self.newTmpUser(user_info = nil)
    tmpUser = TmpUser.new
    tmpUser.id = [*'A'..'Z', *'a'..'z', *0..9].sample(64).join
    t = Time.now
    expiredAt = t + (60 * 10)
    tmpUser.expired_at = expiredAt.utc.to_s
    tmpUser.user_id = user_info.id unless user_info.nil?
    tmpUser.save
    tmpUser # 消してはいけない
  end

  def self.addEmailCredential(email, password, tmp_user_id = nil, user_id = nil)
    c = Credential.new
    c.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
    c.type = 'email'
    c.uid = email
    c.display_name = email
    c.salt = [*'A'..'Z', *'a'..'z', *0..9].sample(21).join
    c.tmp_user_id = tmp_user_id unless tmp_user_id.nil?
    c.user_id = user_id unless user_id.nil?
    c.token = Digest::MD5.hexdigest(c.salt + password)
    c.save
  end

  def self.add_2fa_credential(token, user_id)
    c = Credential.new
    c.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
    c.token = token
    c.type = 'two_factor'
    puts user_id
    c.uid = User.find_by(id: user_id).display_id
    c.user_id = user_id
    c.save
  end

  def self.email(email, password, ip = nil, useragent = nil)
    puts email
    c = Credential.find_by(uid: email, type: 'email', tmp_user_id: nil)
    puts c
    return nil if c.nil?

    token = Digest::MD5.hexdigest(c.salt + password)
    puts token
    return nil if token != c.token

    u = User.find(c.user_id)
    admin_start(u.id, ip, useragent)
  end

  def self.logout(session)
    token = session[:token]
    return token if token.nil?

    session = Session.find_by(token: token)
    return nil if session.nil?

    session.destroy

    true
  end

  def self.admin_start(user_id, ip = nil, useragent = nil)
    s = Session.new
    s.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
    s.token = [*'A'..'Z', *'a'..'z', *0..63].sample(10).join
    s.expired_at = Time.now + (3600 * 24 * 30)
    s.established_at = Time.now
    s.last_used_at = Time.now
    s.ip = ip
    s.useragent = useragent
    s.user_id = user_id
    s.save
    s.token
  end

  def self.newSocialCredential(type, uid, display_name = nil, icon_uri = nil, user_id = nil, tmp_user_id = nil)
    c = Credential.new
    c.id = [*'A'..'Z', *'a'..'z', *0..9].sample(10).join
    c.type = type
    c.uid = uid
    c.display_name = display_name
    c.tmp_user_id = tmp_user_id unless tmp_user_id.nil?
    c.icon_uri = icon_uri
    c.user_id = user_id unless user_id.nil?
    c.save
    c
  end

  def self.socialLogin(session, type, uid, display_name = nil, icon_uri = nil, ip = nil, useragent = nil)
    user_info = self.login(session)
    c = Credential.find_by(type: type, uid: uid, tmp_user_id: nil)
    if user_info.nil?
      if c.nil?
        # アカウント作成
        cs = Credential.where(type: type, uid: uid, user_id: nil)
        cs.each do |c|
          c.destroy
        end
        tmpUser = newTmpUser
        newSocialCredential(type, uid, display_name, icon_uri, nil, tmpUser.id)
        { status: 'account_creation', tmpUser: tmpUser }
      else
        # ログイン
        token = admin_start(c.user_id, ip, useragent)
        { status: 'logged_in', token: token }
      end
    else
      if c.nil?
        newSocialCredential(type, uid, display_name, icon_uri, user_info.id, nil)
        { status: 'method_added' }
      else
        { status: 'already_used_method' }
      end
    end
  end

  def self.socialLoginRedirectTo(session, type, uid, display_name = nil, icon_uri = nil, ip = nil, useragent = nil)
    result = socialLogin(session, type, uid, display_name, icon_uri, ip, useragent)
    case result[:status]
    when 'account_creation'
      '/account/new/' + result[:tmpUser].id + '?suggest_name=' + NetHttp.escape(display_name)
    when 'logged_in'
      session[:token] = result[:token]
      '/'
    when 'method_added'
      '/settings?saved=true'
    when 'already_used_method'
      '/settings?already_used_method=true'
    end
  end
end

class TwoFactorAuth
  def initialize(secret_key)
    @secret_key = secret_key
  end

  def generate_hs(key, counter)
    puts "key: #{key}"
    puts "counter: #{counter}"
    b = []
    while counter > 0
      # puts "b: #{(counter & 0xff)}"
      b.push((counter & 0xff).chr)
      counter >>= 8
    end
    puts 'b----'
    puts b
    puts '-----'
    text = b.reverse.join('').rjust(8, "\0")
    puts "text: #{text}"

    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA1'), Base32.decode(key), text).bytes
  end

  def dynamic_truncate(key, counter, _digit = 6)
    hs = generate_hs(key, counter)
    puts "hs: #{hs}"
    puts "hs19: #{hs[19]}"
    offset = (hs[19] & 0xF)
    puts "offset: #{offset}"
    p = ((hs[offset] & 0x7f) << 24) | ((hs[offset + 1] & 0xff) << 16) | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff))
    p2 = (((hs[offset]) << 24) | ((hs[offset + 1]) << 16) | ((hs[offset + 2]) << 8) | ((hs[offset + 3]))) & 0x7FFFFFFF
    puts "p: #{p}"
    puts "p: #{p2}"
    p
  end

  def HOTP(key, counter, digit = 6)
    sNum = dynamic_truncate(key, counter, digit)
    otp = sNum % (10**6)
    format('%06d', otp)
  end

  def TOTP(time = Time.now, _digit = 6)
    counter = (time.to_i / 30).floor
    puts @secret_key
    puts counter
    HOTP(@secret_key, counter)
  end
end

class TimeControl
  def self.familiar_string(to, from = Time.now, formatted = false)
    return "#{to.year}/#{to.month}/#{to.day} #{to.hour}:#{to.min}:#{to.sec}" if formatted

    if from - to < 1
      '今'
    elsif from - to < 60
      "#{(from - to).to_i}秒前"
    elsif from - to < 3600
      "#{((from - to) / 60).floor}分前"
    elsif from - to < (3600 * 24)
      "#{((from - to) / 3600).floor}時間前"
    elsif from - to < (3600 * 24 * 7)
      "#{((from - to) / (3600 * 24)).floor}日前"
    else
      "#{to.year}/#{to.month}/#{to.day}"
    end
  end
end
