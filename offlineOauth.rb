require "json"
require "./oauth/google"
require "yaml"
require "erb"

credential = YAML.load_file("credential/general.yml")
$redirect_uri = credential["redirect_uri"]
credential = JSON.parse(File.read('credential/googleMailer.json'))
$go = Google.new(credential["installed"]["client_id"], credential["installed"]["client_secret"], "urn:ietf:wg:oauth:2.0:oob", true)
puts "Click link below to start logging in."
puts $go.generate_authorize_uri(
    [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.send"
    ],
    "offline"
)
puts "Input code below."
code = gets
@result = $go.get_accesstoken(code)
puts @result

@result["expires_in"] = Time.now + @result["expires_in"]

File.open("./credential/googleMailerToken.json", mode = "w"){|f|
    f.write(JSON.pretty_generate(@result))  # ファイルに書き込む
}

puts "Done."