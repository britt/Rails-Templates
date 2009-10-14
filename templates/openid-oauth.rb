run "rm public/index.html"

# Gem dependency install
gem 'rspec', :version => '>= 1.2.6', :lib => 'spec'
gem 'rspec-rails', :version => '>= 1.2.6', :lib => 'spec/rails'
gem 'guid', :version => ">= 0.1.1"
gem "haml", :version => ">= 2.2"
gem 'ruby-openid', :version => ">= 2.1.7", :lib => 'openid'
gem 'authlogic-oid', :version => ">= 1.0.4", :lib => "authlogic_openid"
gem 'authlogic', :version => ">= 2.1.2"
rake "gems:install"

# Initialize the git repo so we can use submodules for plugins
git :init

# Install the open id plugin
plugin 'open_id_authentication', :git => 'git://github.com/rails/open_id_authentication.git', :submodule => true
rake "open_id_authentication:db:create"

# Generate user and user_session models
generate :rspec
generate :rspec_model, "user", "email:string", "persistence_token:string", "current_login_at:datetime", "last_login_at:datetime", "openid_identifier:string"
generate :session, "user_session"

git :add => "."
git :commit => "-a -m 'Initial commit'"
