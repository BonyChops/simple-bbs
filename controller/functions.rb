require "base32"
require "./oauth/http"

class SessionManager
    def self.login(session)
        token = session[:token]
        if token == nil
            return token
        end
        session = Session.find_by(token: token)
        if session == nil
            return nil
        end

        return User.find(session.user_id)
    end

    def self.newTmpUser
        tmpUser = TmpUser.new
        tmpUser.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..63].join
        t = Time.now
        expiredAt =  t + (60 * 10)
        puts expiredAt
        tmpUser.expired_at = (expiredAt).utc.to_s
        puts (expiredAt).utc.to_s
        puts tmpUser.expired_at
        puts "----------"
        tmpUser.save
        return tmpUser
    end

    def self.addEmailCredential(email, password, tmp_user_id = nil, user_id = nil)
        c = Credential.new
        c.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
        c.type = "email"
        c.uid = email
        c.display_name = email
        c.salt = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..20].join
        c.tmp_user_id = tmp_user_id if tmp_user_id != nil
        c.user_id = user_id if user_id != nil
        c.token = Digest::MD5.hexdigest(c.salt + password)
        c.save
    end

    def self.email(email, password, ip = nil, useragent = nil)
        puts email
        c = Credential.find_by(uid: email, type: "email")
        puts c
        return nil if c == nil
        token = Digest::MD5.hexdigest(c.salt + password)
        puts token
        return nil if token != c.token
        u = User.find(c.user_id)
        return self.admin_start(u.id, ip, useragent)
    end


    def self.logout(session)
        token = session[:token]
        if token == nil
            return token
        end
        session = Session.find_by(token: token)
        if session == nil
            return nil
        end
        session.destroy

        return true
    end

    def self.admin_start(user_id, ip = nil, useragent = nil)
        s = Session.new
        s.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
        s.token = [*'A'..'Z', *'a'..'z', *0..63].shuffle[0..9].join
        s.expired_at = Time.now + (3600 * 24 * 30)
        s.established_at = Time.now
        s.last_used_at = Time.now
        s.ip = ip
        s.useragent = useragent
        s.user_id = user_id
        s.save
        return s.token
    end

    def self.newSocialCredential(type, uid, display_name = nil, icon_uri = nil, user_id = nil, tmp_user_id = nil)
        c = Credential.new
        c.id = [*'A'..'Z', *'a'..'z', *0..9].shuffle[0..9].join
        c.type = type
        c.uid = uid
        c.display_name = display_name
        c.tmp_user_id = tmp_user_id if tmp_user_id != nil
        c.icon_uri = icon_uri
        c.user_id = user_id if user_id != nil
        c.save
        return c
    end

    def self.socialLogin(type, uid, display_name = nil, icon_uri = nil, ip = nil, useragent = nil)
        c = Credential.all.find_by(type: type, uid: uid, tmp_user_id: nil)
        if c == nil
            # アカウント作成
            cs = Credential.where(type: type, uid: uid, user_id: nil)
            cs.each do |c|
                c.destroy
            end
            tmpUser = self.newTmpUser
            self.newSocialCredential(type, uid, display_name, icon_uri, nil, tmpUser.id)
            return {status: "account_creation", tmpUser: tmpUser}
        else
            # ログイン
            token = self.admin_start(c.user_id, ip, useragent)
            return {status: "logged_in", token: token}
        end
    end

    def self.socialLoginRedirectTo(session, type, uid, display_name = nil, icon_uri = nil, ip = nil, useragent = nil)
        result = self.socialLogin(type, uid, display_name, icon_uri, ip, useragent)
        case result[:status]
        when "account_creation"
            return "/account/new/" + result[:tmpUser].id + "?suggest_name=" + NetHttp.escape(display_name)
        when "logged_in"
            session[:token] = result[:token]
            return "/"
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
        while counter > 0 do
            # puts "b: #{(counter & 0xff)}"
            b.push((counter & 0xff).chr)
            counter >>= 8
        end
        puts "b----"
        puts b
        puts "-----"
        text = b.reverse.join("").rjust(8, "\0")
        puts "text: #{text}"

        return OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, Base32.decode(key), text).bytes
    end

    def dynamic_truncate(key, counter, digit = 6)
        hs = generate_hs(key, counter)
        puts "hs: #{hs}"
        puts "hs19: #{hs[19]}"
        offset = (hs[19] & 0xF)
        puts "offset: #{offset}"
        p = ((hs[offset] & 0x7f) << 24) | ((hs[offset + 1] & 0xff) << 16) | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff))
        p2 =( ((hs[offset]) << 24) | ((hs[offset + 1]) << 16) | ((hs[offset + 2]) << 8) | ((hs[offset + 3]))) & 0x7FFFFFFF
        puts "p: #{p}"
        puts "p: #{p2}"
        return p
    end

    def HOTP(key, counter, digit = 6)
        sNum = dynamic_truncate(key, counter, digit)
        otp = sNum % (10 ** 6)
        return sprintf("%06d", otp)
    end

    def TOTP(time = Time.now, digit = 6)
        counter = (time.to_i / 30).floor
        puts @secret_key
        puts counter
        return HOTP(@secret_key, counter)
    end
end