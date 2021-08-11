require "sinatra"
require "sinatra/reloader"
require "active_record"

use Rack::MethodOverride

set :environment , :production

ActiveRecord::Base.configurations = YAML.load_file("database.yml")
ActiveRecord::Base.establish_connection :development

class Users < ActiveRecord::Base
end

class Tokens < ActiveRecord::Base
end

get "/" do
    erb :index
end

get "/login" do
    @incorrectFlag = params[:incorrect]
    puts @incorrectFlag
    erb :login
end

post "/session" do
    redirect "/login?incorrect=true"
end