# template.rb
run "rm public/index.html"

gem 'rspec', :version => '>= 1.2.6', :lib => 'spec'
gem 'rspec-rails', :version => '>= 1.2.6', :lib => 'spec/rails'
gem 'guid', :version => ">= 0.1.1"
gem "haml", :version => ">= 2.2"
gem 'ruby-openid', :version => ">= 2.1.7", :lib => 'openid'
gem 'authlogic', :version => ">= 2.1.2"

rake "gems:install"

git :init
git :add => "."
git :commit => "-a -m 'Initial commit'"
