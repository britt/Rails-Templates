# Basic configuration using bundler
run "rm public/index.html"

git :init

file 'Gemfile', <<-Gemfile
source "http://gems.github.com"
disable_system_gems

gem "rails", "2.3.5"
gem "haml", ">= 2.2.9"

gem "rspec", :only => :testing
gem "rspec-rails", :lib => 'spec/rails', :only => :testing
Gemfile

file 'config/preinitializer.rb', <<-Preinitializer
  require "\#\{RAILS_ROOT\}/vendor/gems/environment"
Preinitializer

generate :rspec
run "rm -rf test"

git :add => "."
git :commit => "-a -m 'Initial commit'"
