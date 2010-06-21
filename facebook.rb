git :init

file "Gemfile", <<-GEMFILE
  source 'http://gems.rubygems.org'

  gem "rails", "3.0.0.beta4"
  gem "bundler", ">= 0.9.26"
  gem 'haml', '>= 2.2.21'
  gem 'rails_warden', '>= 0.5.1'
  gem 'json_pure', '>= 1.2.0'
  gem 'rest-client', '>= 1.5.1', :require => 'rest_client'

  group :production do
    gem 'pg', '>= 0.9.0'
  end

  group :development do 
    gem "sqlite3-ruby", :require => "sqlite3"
    gem "mongrel"
  end

  group :test do
    gem 'turn'
    gem 'faker'
    gem 'ruby-debug'
    # Don't require factory girl because it loads all the factories, some of which 
    # might depend on Faker which loads AFTER factory_girl.
    gem 'factory_girl', :git => 'git://github.com/thoughtbot/factory_girl.git', :branch => 'rails3', :require => false
  end
GEMFILE

run "bundle install"

# Gemfile
# application.rb customizations
# warden files
# layout
# facebook login
# facebook js
# jquery
# User model
# shoulda patches
# test_helper cahnges
