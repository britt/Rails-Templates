run "rm public/index.html"

# Gem dependency install
gem 'rspec', :version => '>= 1.2.6', :lib => 'spec'
gem 'rspec-rails', :version => '>= 1.2.6', :lib => 'spec/rails'
gem 'machinist', :source => 'http://gemcutter.org'
gem 'guid', :version => ">= 0.1.1"
gem "haml", :version => ">= 2.2"
gem 'ruby-openid', :version => ">= 2.1.7", :lib => 'openid'
gem 'authlogic-oid', :version => ">= 1.0.4", :lib => "authlogic_openid"
gem 'authlogic', :version => ">= 2.1.2"
gem "oauth"
gem "oauth-plugin"
rake "gems:install"

# Initialize the git repo so we can use submodules for plugins
git :init

# Install the open id plugin
plugin 'open_id_authentication', :git => 'git://github.com/rails/open_id_authentication.git', :submodule => true
rake "open_id_authentication:db:create"

git :add => "."
git :commit => "-a -m 'Initial commit'"
